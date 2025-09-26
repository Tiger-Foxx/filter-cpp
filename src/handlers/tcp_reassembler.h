#ifndef TCP_REASSEMBLER_H
#define TCP_REASSEMBLER_H

#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <deque>
#include <map>

// Forward declarations
struct PacketData;

struct HTTPData {
    std::string method;
    std::string uri;
    std::string version;
    std::unordered_map<std::string, std::string> headers;
    std::string payload;
    std::string user_agent;
    std::string host;
    bool complete = false;
};

struct TCPSegment {
    uint32_t seq_num;
    std::string data;
    uint64_t timestamp;
    
    bool operator<(const TCPSegment& other) const {
        return seq_num < other.seq_num;
    }
};

class TCPStream {
private:
    std::string src_ip_;
    uint16_t src_port_;
    std::string dst_ip_;
    uint16_t dst_port_;
    
    // Stream reassembly
    std::map<uint32_t, TCPSegment> segments_;
    uint32_t next_expected_seq_;
    std::string assembled_data_;
    uint64_t last_activity_;
    
    // HTTP parsing state
    bool http_detected_;
    bool in_headers_;
    std::string current_request_;
    int content_length_;
    int body_received_;
    
    mutable std::mutex stream_mutex_;

public:
    TCPStream(const std::string& src_ip, uint16_t src_port, 
              const std::string& dst_ip, uint16_t dst_port);
    
    ~TCPStream() = default;
    
    // Add TCP segment to stream
    std::unique_ptr<HTTPData> AddSegment(uint32_t seq_num, const std::string& data);
    
    // Check if stream is expired
    bool IsExpired(uint64_t timeout_ms) const;
    
    // Get stream key for identification
    std::string GetKey() const;
    
    // Stream info
    std::string GetInfo() const;
    
private:
    void AssembleSegments();
    bool DetectHTTP();
    std::unique_ptr<HTTPData> ParseHTTP();
    std::unique_ptr<HTTPData> ParseHTTPRequest(const std::string& data);
    uint64_t GetCurrentTimeMs() const;
    void UpdateActivity();
};

class TCPReassembler {
private:
    std::unordered_map<std::string, std::unique_ptr<TCPStream>> streams_;
    mutable std::mutex streams_mutex_;
    
    // Configuration
    size_t max_streams_;
    uint64_t stream_timeout_ms_;
    
    // Cleanup thread
    std::thread cleanup_thread_;
    std::atomic<bool> cleanup_running_;
    
    // Statistics
    std::atomic<uint64_t> total_streams_;
    std::atomic<uint64_t> active_streams_;
    std::atomic<uint64_t> http_streams_;
    std::atomic<uint64_t> reassembled_requests_;
    std::atomic<uint64_t> expired_streams_;

public:
    explicit TCPReassembler(size_t max_streams = 10000, uint64_t timeout_ms = 30000);
    ~TCPReassembler();
    
    // Process incoming packet and try to reassemble HTTP
    std::unique_ptr<HTTPData> ProcessPacket(unsigned char* data, int len, const PacketData& packet);
    
    // Statistics
    struct Stats {
        uint64_t total_streams = 0;
        uint64_t active_streams = 0;
        uint64_t http_streams = 0;
        uint64_t reassembled_requests = 0;
        uint64_t expired_streams = 0;
    };
    
    Stats GetStats() const;
    void PrintStats() const;
    
    // Cleanup
    void Cleanup();

private:
    std::string GetStreamKey(const PacketData& packet) const;
    void CleanupExpiredStreams();
    void CleanupLoop();
    TCPStream* GetOrCreateStream(const std::string& key, const PacketData& packet);
    std::string ExtractTCPPayload(unsigned char* data, int len, const PacketData& packet) const;
};

#endif // TCP_REASSEMBLER_H