#ifndef HYBRID_ENGINE_H
#define HYBRID_ENGINE_H

#include "rule_engine.h"
#include <memory>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>

// Forward declarations
class TCPReassembler;

// Work item pour dispatch vers workers
struct WorkItem {
    PacketData packet;
    std::function<void(FilterResult)> callback;
    uint64_t timestamp_ns;
    uint32_t flow_hash;
    
    WorkItem(const PacketData& pkt, std::function<void(FilterResult)> cb) 
        : packet(pkt), callback(cb) {
        timestamp_ns = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        // Hash pour dispatch (4-tuple)
        std::hash<std::string> hasher;
        std::string flow_key = packet.src_ip + ":" + std::to_string(packet.src_port) + 
                              "-" + packet.dst_ip + ":" + std::to_string(packet.dst_port);
        flow_hash = hasher(flow_key);
    }
};

class HybridEngine : public RuleEngine {
private:
    // Multi-worker architecture avec hash dispatch
    std::vector<std::thread> worker_threads_;
    std::vector<std::unique_ptr<std::queue<std::unique_ptr<WorkItem>>>> worker_queues_;
    std::vector<std::unique_ptr<std::mutex>> queue_mutexes_;
    std::vector<std::unique_ptr<std::condition_variable>> queue_conditions_;
    std::atomic<bool> workers_running_{false};
    
    // Chaque worker a son propre TCP reassembler pour éviter les locks
    std::vector<std::unique_ptr<TCPReassembler>> worker_reassemblers_;
    
    size_t num_workers_;
    
    // Performance tracking spécifique hybrid
    std::atomic<uint64_t> dispatched_packets_{0};
    std::atomic<uint64_t> queue_full_drops_{0};
    std::vector<std::atomic<uint64_t>> worker_packet_counts_;
    std::vector<std::atomic<double>> worker_avg_times_;
    mutable std::atomic<size_t> next_worker_id_{0};
    
    static constexpr size_t MAX_QUEUE_SIZE = 10000; // Par worker

public:
    explicit HybridEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                         size_t num_workers = 0);
    
    ~HybridEngine() override;
    
    bool Initialize() override;
    void Shutdown() override;
    
    // Interface principale - dispatch vers workers
    FilterResult FilterPacket(const PacketData& packet) override;
    
    // Interface asynchrone pour haute performance
    bool FilterPacketAsync(const PacketData& packet, std::function<void(FilterResult)> callback);
    
    void PrintPerformanceStats() const override;

private:
    // Worker management
    void WorkerLoop(size_t worker_id);
    size_t GetOptimalWorkerCount() const;
    void InitializeWorkers();
    void ShutdownWorkers();
    
    // Hash-based dispatch
    size_t DispatchToWorker(uint32_t flow_hash) const;
    size_t DispatchToWorkerOptimized(const PacketData& packet) const;
    bool EnqueueWork(size_t worker_id, std::unique_ptr<WorkItem> work);
    
    // Per-worker processing (séquentiel L3→L4→L7 par worker)
    FilterResult ProcessPacketSequential(const PacketData& packet, size_t worker_id);
    
    void UpdateWorkerStats(size_t worker_id, double processing_time);
    void SetWorkerAffinity(size_t worker_id);
};

#endif // HYBRID_ENGINE_H