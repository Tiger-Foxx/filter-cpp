#ifndef WORKER_POOL_H
#define WORKER_POOL_H

#include "rule_engine.h"

#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <memory>
#include <future>

// Forward declarations
class RuleEngine;

// Work item for packet processing
struct PacketWorkItem {
    PacketData packet_data;
    std::promise<FilterResult> result_promise;
    uint64_t timestamp_ns;
    
    PacketWorkItem(const PacketData& packet) 
        : packet_data(packet) {
        timestamp_ns = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    }
};

class WorkerPool {
private:
    // Worker threads
    std::vector<std::thread> worker_threads_;
    size_t num_workers_;
    
    // Work queue
    std::queue<std::unique_ptr<PacketWorkItem>> work_queue_;
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_condition_;
    std::atomic<bool> workers_running_{false};
    
    // Rule engine (shared among workers)
    std::shared_ptr<RuleEngine> rule_engine_;
    
    // Load balancing and affinity
    std::atomic<size_t> next_worker_id_{0};
    std::vector<std::atomic<uint64_t>> worker_packet_counts_;
    std::vector<std::atomic<double>> worker_avg_times_;
    
    // Queue management
    size_t max_queue_size_;
    std::atomic<uint64_t> enqueued_packets_{0};
    std::atomic<uint64_t> dequeued_packets_{0};
    std::atomic<uint64_t> dropped_queue_full_{0};
    
    // Performance monitoring
    std::atomic<uint64_t> total_processing_time_ns_{0};
    std::atomic<uint64_t> processed_packets_{0};

public:
    struct Stats {
        size_t num_workers = 0;
        size_t queue_size = 0;
        size_t max_queue_size = 0;
        uint64_t enqueued_packets = 0;
        uint64_t dequeued_packets = 0;
        uint64_t dropped_queue_full = 0;
        uint64_t processed_packets = 0;
        double avg_processing_time_ms = 0.0;
        double queue_utilization_percent = 0.0;
        std::vector<uint64_t> worker_packet_counts;
        std::vector<double> worker_avg_times_ms;
    };

    explicit WorkerPool(std::shared_ptr<RuleEngine> rule_engine, 
                       size_t num_workers = 0, 
                       size_t max_queue_size = 100000);
    
    ~WorkerPool();
    
    // Start/stop worker pool
    bool Start();
    void Stop();
    bool IsRunning() const { return workers_running_.load(); }
    
    // Submit packet for processing (async)
    std::future<FilterResult> SubmitPacket(const PacketData& packet);
    
    // Submit packet for processing (sync with timeout)
    FilterResult ProcessPacket(const PacketData& packet, 
                              std::chrono::milliseconds timeout = std::chrono::milliseconds(1000));
    
    // Statistics and monitoring
    Stats GetStats() const;
    void PrintStats() const;
    void ResetStats();
    
    // Configuration
    size_t GetWorkerCount() const { return num_workers_; }
    void SetMaxQueueSize(size_t max_size) { max_queue_size_ = max_size; }

private:
    void WorkerLoop(size_t worker_id);
    size_t GetOptimalWorkerCount() const;
    void SetWorkerAffinity(size_t worker_id);
    bool EnqueueWork(std::unique_ptr<PacketWorkItem> work_item);
    std::unique_ptr<PacketWorkItem> DequeueWork();
    void UpdateWorkerStats(size_t worker_id, double processing_time_ms);
};

#endif // WORKER_POOL_H