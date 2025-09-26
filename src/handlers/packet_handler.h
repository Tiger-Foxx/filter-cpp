#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <memory>
#include <atomic>
#include <functional>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <netinet/in.h>

extern "C" {
    #include <libnetfilter_queue/libnetfilter_queue.h>
    #include <linux/netfilter.h>
}

// Forward declarations
class RuleEngine;
class TCPReassembler;
struct PacketData;
struct FilterResult;

class PacketHandler {
private:
    int queue_num_;
    bool debug_mode_;
    std::atomic<bool> running_{false};
    
    // NFQUEUE handles
    struct nfq_handle* nfq_handle_;
    struct nfq_q_handle* queue_handle_;
    int netlink_fd_;
    
    // Core components
    RuleEngine* rule_engine_;
    std::unique_ptr<TCPReassembler> tcp_reassembler_;
    
    // Connection tracking for efficiency
    std::unordered_set<uint64_t> blocked_connections_;
    mutable std::mutex connections_mutex_;
    
    // HTTP ports for L7 analysis
    std::unordered_set<uint16_t> http_ports_{80, 443, 8080, 8443, 8000, 3000, 5000};
    
    // Statistics
    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> dropped_packets_{0};
    std::atomic<uint64_t> accepted_packets_{0};
    std::atomic<uint64_t> reassembled_packets_{0};
    std::atomic<uint64_t> early_detection_hits_{0};
    
    // Callback for packet processing results
    std::function<void(bool)> packet_callback_;
    
public:
    struct Stats {
        uint64_t total_packets = 0;
        uint64_t dropped_packets = 0;
        uint64_t accepted_packets = 0;
        uint64_t reassembled_packets = 0;
        uint64_t early_detection_hits = 0;
        double drop_rate = 0.0;
        double reassembly_rate = 0.0;
        size_t blocked_connections = 0;
    };

    explicit PacketHandler(int queue_num, RuleEngine* rule_engine, bool debug_mode = false);
    ~PacketHandler();
    
    // Main interface
    bool Initialize();
    void Start(std::function<void(bool)> callback);
    void Stop();
    
    // Configuration
    void SetDebugMode(bool debug) { debug_mode_ = debug; }
    
    // Statistics
    Stats GetStats() const;
    void PrintStats() const;
    
    // NFQUEUE callback (called from C)
    int HandlePacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa);

private:
    // Packet processing
    bool ParsePacket(unsigned char* data, int len, PacketData& packet);
    bool NeedsHTTPReassembly(const PacketData& packet);
    void HandleTCPReassembly(unsigned char* data, int len, PacketData& packet);
    
    // Connection management
    uint64_t GetConnectionKey(const PacketData& packet);
    bool IsConnectionBlocked(uint64_t connection_key);
    void BlockConnection(uint64_t connection_key);
    
    // Network utilities
    std::string ExtractIPAddress(uint32_t ip_addr);
    uint16_t ExtractPort(const void* transport_header, bool is_tcp);
};

#endif // PACKET_HANDLER_H