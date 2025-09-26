#include "worker_pool.h"
#include "rule_engine.h"
#include "../utils.h"

#include <iostream>
#include <algorithm>
#include <chrono>
#include <iomanip>

WorkerPool::WorkerPool(std::shared_ptr<RuleEngine> rule_engine, size_t num_workers, size_t max_queue_size)
    : rule_engine_(rule_engine), max_queue_size_(max_queue_size),
      worker_packet_counts_(num_workers > 0 ? num_workers : GetOptimalWorkerCount()),
      worker_avg_times_(num_workers > 0 ? num_workers : GetOptimalWorkerCount()) {
    
    if (num_workers == 0) {
        num_workers_ = GetOptimalWorkerCount();
    } else {
        num_workers_ = num_workers;
    }
    
    std::cout << "🔧 WorkerPool initialized:" << std::endl;
    std::cout << "   Workers: " << num_workers_ << std::endl;
    std::cout << "   Max queue size: " << max_queue_size_ << std::endl;
    std::cout << "   CPU cores: " << std::thread::hardware_concurrency() << std::endl;
}

WorkerPool::~WorkerPool() {
    Stop();
}

bool WorkerPool::Start() {
    if (workers_running_.load()) {
        std::cout << "⚠️  WorkerPool already running" << std::endl;
        return true;
    }
    
    if (!rule_engine_) {
        std::cerr << "❌ Error: No rule engine provided to WorkerPool" << std::endl;
        return false;
    }
    
    workers_running_.store(true);
    
    // Start worker threads
    for (size_t i = 0; i < num_workers_; ++i) {
        worker_threads_.emplace_back(&WorkerPool::WorkerLoop, this, i);
        
        // Set CPU affinity if possible
        SetWorkerAffinity(i);
    }
    
    std::cout << "✅ WorkerPool started with " << num_workers_ << " workers" << std::endl;
    return true;
}

void WorkerPool::Stop() {
    if (!workers_running_.load()) {
        return;
    }
    
    std::cout << "🛑 Stopping WorkerPool..." << std::endl;
    
    workers_running_.store(false);
    
    // Wake up all workers
    queue_condition_.notify_all();
    
    // Wait for all workers to finish
    for (auto& worker : worker_threads_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    worker_threads_.clear();
    
    // Clear remaining work queue
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        while (!work_queue_.empty()) {
            auto work_item = std::move(work_queue_.front());
            work_queue_.pop();
            
            // Set error result for pending work
            FilterResult error_result;
            error_result.action = RuleAction::ACCEPT;
            error_result.rule_id = "worker_pool_shutdown";
            error_result.matched_layer = RuleLayer::L3;
            error_result.decision_time_ms = 0.0;
            error_result.early_termination = false;
            
            try {
                work_item->result_promise.set_value(error_result);
            } catch (...) {
                // Ignore if promise already set
            }
        }
    }
    
    std::cout << "✅ WorkerPool stopped" << std::endl;
}

std::future<FilterResult> WorkerPool::SubmitPacket(const PacketData& packet) {
    auto work_item = std::make_unique<PacketWorkItem>(packet);
    auto future = work_item->result_promise.get_future();
    
    if (!EnqueueWork(std::move(work_item))) {
        // Queue is full, return immediate ACCEPT
        std::promise<FilterResult> promise;
        FilterResult result;
        result.action = RuleAction::ACCEPT;
        result.rule_id = "queue_full";
        result.matched_layer = RuleLayer::L3;
        result.decision_time_ms = 0.0;
        result.early_termination = false;
        
        promise.set_value(result);
        return promise.get_future();
    }
    
    enqueued_packets_.fetch_add(1, std::memory_order_relaxed);
    return future;
}

FilterResult WorkerPool::ProcessPacket(const PacketData& packet, std::chrono::milliseconds timeout) {
    auto future = SubmitPacket(packet);
    
    if (future.wait_for(timeout) == std::future_status::timeout) {
        // Timeout - return ACCEPT to avoid blocking network
        FilterResult timeout_result;
        timeout_result.action = RuleAction::ACCEPT;
        timeout_result.rule_id = "timeout";
        timeout_result.matched_layer = RuleLayer::L3;
        timeout_result.decision_time_ms = static_cast<double>(timeout.count());
        timeout_result.early_termination = true;
        return timeout_result;
    }
    
    try {
        return future.get();
    } catch (const std::exception& e) {
        // Error in processing - return ACCEPT
        FilterResult error_result;
        error_result.action = RuleAction::ACCEPT;
        error_result.rule_id = "processing_error";
        error_result.matched_layer = RuleLayer::L3;
        error_result.decision_time_ms = 0.0;
        error_result.early_termination = false;
        return error_result;
    }
}

WorkerPool::Stats WorkerPool::GetStats() const {
    Stats stats;
    stats.num_workers = num_workers_;
    stats.max_queue_size = max_queue_size_;
    stats.enqueued_packets = enqueued_packets_.load();
    stats.dequeued_packets = dequeued_packets_.load();
    stats.dropped_queue_full = dropped_queue_full_.load();
    stats.processed_packets = processed_packets_.load();
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        stats.queue_size = work_queue_.size();
    }
    
    stats.queue_utilization_percent = (static_cast<double>(stats.queue_size) / max_queue_size_) * 100.0;
    
    // Calculate average processing time
    auto total_time = total_processing_time_ns_.load();
    auto processed = processed_packets_.load();
    if (processed > 0) {
        stats.avg_processing_time_ms = (total_time / 1000000.0) / processed; // Convert ns to ms
    }
    
    // Collect per-worker stats
    stats.worker_packet_counts.resize(num_workers_);
    stats.worker_avg_times_ms.resize(num_workers_);
    
    for (size_t i = 0; i < num_workers_; ++i) {
        stats.worker_packet_counts[i] = worker_packet_counts_[i].load();
        stats.worker_avg_times_ms[i] = worker_avg_times_[i].load();
    }
    
    return stats;
}

void WorkerPool::PrintStats() const {
    auto stats = GetStats();
    
    std::cout << "\n🔧 WorkerPool Statistics:" << std::endl;
    std::cout << "   Workers: " << stats.num_workers << std::endl;
    std::cout << "   Current queue size: " << stats.queue_size << "/" << stats.max_queue_size << std::endl;
    std::cout << "   Queue utilization: " << std::fixed << std::setprecision(1) 
              << stats.queue_utilization_percent << "%" << std::endl;
    std::cout << "   Enqueued packets: " << stats.enqueued_packets << std::endl;
    std::cout << "   Processed packets: " << stats.processed_packets << std::endl;
    std::cout << "   Dropped (queue full): " << stats.dropped_queue_full << std::endl;
    std::cout << "   Avg processing time: " << std::fixed << std::setprecision(3) 
              << stats.avg_processing_time_ms << " ms" << std::endl;
    
    std::cout << "   Per-worker stats:" << std::endl;
    for (size_t i = 0; i < stats.worker_packet_counts.size(); ++i) {
        std::cout << "     Worker " << i << ": " << stats.worker_packet_counts[i] 
                  << " packets, " << std::fixed << std::setprecision(3) 
                  << stats.worker_avg_times_ms[i] << " ms avg" << std::endl;
    }
}

void WorkerPool::ResetStats() {
    enqueued_packets_.store(0);
    dequeued_packets_.store(0);
    dropped_queue_full_.store(0);
    processed_packets_.store(0);
    total_processing_time_ns_.store(0);
    
    for (size_t i = 0; i < num_workers_; ++i) {
        worker_packet_counts_[i].store(0);
        worker_avg_times_[i].store(0.0);
    }
}

void WorkerPool::WorkerLoop(size_t worker_id) {
    LOG_DEBUG(true, "Worker " + std::to_string(worker_id) + " started");
    
    while (workers_running_.load()) {
        auto work_item = DequeueWork();
        
        if (!work_item) {
            // No work available, wait a bit
            continue;
        }
        
        // Process the packet
        HighResTimer timer;
        
        try {
            // Use rule engine to filter packet (sequential mode within worker)
            FilterResult result = rule_engine_->FilterPacket(work_item->packet_data);
            
            double processing_time_ms = timer.ElapsedMilliseconds();
            
            // Update worker stats
            UpdateWorkerStats(worker_id, processing_time_ms);
            
            // Set result
            work_item->result_promise.set_value(result);
            
        } catch (const std::exception& e) {
            LOG_DEBUG(true, "Worker " + std::to_string(worker_id) + " error: " + e.what());
            
            // Return ACCEPT on error to avoid breaking network
            FilterResult error_result;
            error_result.action = RuleAction::ACCEPT;
            error_result.rule_id = "worker_error";
            error_result.matched_layer = RuleLayer::L3;
            error_result.decision_time_ms = timer.ElapsedMilliseconds();
            error_result.early_termination = false;
            
            try {
                work_item->result_promise.set_value(error_result);
            } catch (...) {
                // Ignore if promise already set
            }
        }
    }
    
    LOG_DEBUG(true, "Worker " + std::to_string(worker_id) + " stopped");
}

size_t WorkerPool::GetOptimalWorkerCount() const {
    auto cores = std::thread::hardware_concurrency();
    if (cores <= 2) return 2;
    if (cores <= 4) return cores;
    return cores - 1; // Leave one core for system/main thread
}

void WorkerPool::SetWorkerAffinity(size_t worker_id) {
    if (worker_id >= worker_threads_.size()) return;
    
    #ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    
    // Distribute workers across available cores
    auto cores = std::thread::hardware_concurrency();
    if (cores > 0) {
        size_t target_core = worker_id % cores;
        CPU_SET(target_core, &cpuset);
        
        int rc = pthread_setaffinity_np(worker_threads_[worker_id].native_handle(), 
                                       sizeof(cpu_set_t), &cpuset);
        if (rc == 0) {
            LOG_DEBUG(true, "Worker " + std::to_string(worker_id) + 
                           " bound to CPU core " + std::to_string(target_core));
        } else {
            LOG_DEBUG(true, "Failed to set affinity for worker " + std::to_string(worker_id));
        }
    }
    #endif
}

bool WorkerPool::EnqueueWork(std::unique_ptr<PacketWorkItem> work_item) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    
    if (work_queue_.size() >= max_queue_size_) {
        // Queue is full
        dropped_queue_full_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    
    work_queue_.push(std::move(work_item));
    queue_condition_.notify_one(); // Wake up one worker
    
    return true;
}

std::unique_ptr<PacketWorkItem> WorkerPool::DequeueWork() {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    
    // Wait for work or shutdown signal
    queue_condition_.wait(lock, [this] { 
        return !work_queue_.empty() || !workers_running_.load(); 
    });
    
    if (!workers_running_.load()) {
        return nullptr; // Shutting down
    }
    
    if (work_queue_.empty()) {
        return nullptr; // Spurious wakeup
    }
    
    auto work_item = std::move(work_queue_.front());
    work_queue_.pop();
    
    dequeued_packets_.fetch_add(1, std::memory_order_relaxed);
    
    return work_item;
}

void WorkerPool::UpdateWorkerStats(size_t worker_id, double processing_time_ms) {
    if (worker_id >= num_workers_) return;
    
    // Update global stats
    processed_packets_.fetch_add(1, std::memory_order_relaxed);
    total_processing_time_ns_.fetch_add(
        static_cast<uint64_t>(processing_time_ms * 1000000), // Convert ms to ns
        std::memory_order_relaxed
    );
    
    // Update per-worker stats
    auto current_count = worker_packet_counts_[worker_id].fetch_add(1, std::memory_order_relaxed);
    
    // Update running average for this worker
    double current_avg = worker_avg_times_[worker_id].load();
    double new_avg = ((current_avg * current_count) + processing_time_ms) / (current_count + 1);
    worker_avg_times_[worker_id].store(new_avg);
}