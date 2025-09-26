#include "hybrid_engine.h"
#include "../handlers/tcp_reassembler.h"
#include "../utils.h"

#include <iomanip>
#include <future>
#include <iostream>
#include <algorithm>
#include <chrono>

HybridEngine::HybridEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                          size_t num_workers)
    : RuleEngine(rules, FilterMode::HYBRID) {
    
    if (num_workers == 0) {
        num_workers_ = GetOptimalWorkerCount();
    } else {
        num_workers_ = num_workers;
    }
    
    // Initialize per-worker data structures
    worker_queues_.resize(num_workers_);
    queue_mutexes_.resize(num_workers_);
    queue_conditions_.resize(num_workers_);
    worker_reassemblers_.resize(num_workers_);
    worker_packet_counts_.resize(num_workers_);
    worker_avg_times_.resize(num_workers_);
    
    for (size_t i = 0; i < num_workers_; ++i) {
        worker_packet_counts_[i].store(0);
        worker_avg_times_[i].store(0.0);
    }
    
    std::cout << "🔥 Hybrid Engine initialized:" << std::endl;
    std::cout << "   Workers: " << num_workers_ << std::endl;
    std::cout << "   Architecture: Round-robin dispatch with TCP affinity" << std::endl;
    std::cout << "   TCP Reassembly: Per-worker (no locks)" << std::endl;
    std::cout << "   wrk-optimized: Multiple workers will be used" << std::endl;
}

HybridEngine::~HybridEngine() {
    Shutdown();
}

bool HybridEngine::Initialize() {
    InitializeWorkers();
    std::cout << "✅ Hybrid Multi-Worker Engine started with " << num_workers_ << " workers" << std::endl;
    return true;
}

void HybridEngine::Shutdown() {
    ShutdownWorkers();
    std::cout << "🛑 Hybrid Engine shutdown complete" << std::endl;
}

FilterResult HybridEngine::FilterPacket(const PacketData& packet) {
    // Pour interface synchrone, on utilise une promesse
    std::promise<FilterResult> promise;
    auto future = promise.get_future();
    
    bool dispatched = FilterPacketAsync(packet, [&promise](FilterResult result) {
        promise.set_value(result);
    });
    
    if (!dispatched) {
        // Queue pleine, retour immédiat ACCEPT pour éviter blocage réseau
        FilterResult overload_result;
        overload_result.action = RuleAction::ACCEPT;
        overload_result.rule_id = "queue_overload";
        overload_result.matched_layer = RuleLayer::L3;
        overload_result.decision_time_ms = 0.0;
        overload_result.early_termination = false;
        return overload_result;
    }
    
    return future.get();
}

bool HybridEngine::FilterPacketAsync(const PacketData& packet, std::function<void(FilterResult)> callback) {
    dispatched_packets_.fetch_add(1, std::memory_order_relaxed);
    
    // Créer work item
    auto work_item = std::make_unique<WorkItem>(packet, callback);
    
    // NOUVEAU : Dispatcher optimisé pour wrk et TCP reassembly
    size_t worker_id = DispatchToWorkerOptimized(packet);
    
    return EnqueueWork(worker_id, std::move(work_item));
}

size_t HybridEngine::DispatchToWorkerOptimized(const PacketData& packet) const {
    // Pour HTTP/TCP : grouper par connexion pour TCP reassembly
    if (packet.protocol == 6) { // TCP
        // Hash sur source port + destination pour distribuer les connexions
        // Ceci permet à wrk (qui utilise plein de ports source) de distribuer sur tous workers
        std::string connection_key = std::to_string(packet.src_port) + ":" + std::to_string(packet.dst_port);
        std::hash<std::string> hasher;
        uint32_t hash_value = hasher(connection_key);
        return hash_value % num_workers_;
    }
    
    // Pour autres protocoles : round-robin simple et rapide
    return next_worker_id_.fetch_add(1, std::memory_order_relaxed) % num_workers_;
}

void HybridEngine::InitializeWorkers() {
    workers_running_.store(true);
    
    // Créer TCP reassemblers per-worker (évite les locks)
    for (size_t i = 0; i < num_workers_; ++i) {
        worker_reassemblers_[i] = std::make_unique<TCPReassembler>(1000, 30000); // 1000 streams, 30s timeout
    }
    
    // Démarrer worker threads
    for (size_t i = 0; i < num_workers_; ++i) {
        worker_threads_.emplace_back(&HybridEngine::WorkerLoop, this, i);
        SetWorkerAffinity(i);
    }
    
    std::cout << "🚀 " << num_workers_ << " workers started with CPU affinity" << std::endl;
}

void HybridEngine::WorkerLoop(size_t worker_id) {
    LOG_DEBUG(true, "Worker " + std::to_string(worker_id) + " started");
    
    while (workers_running_.load()) {
        std::unique_ptr<WorkItem> work_item;
        
        // Attendre du travail
        {
            std::unique_lock<std::mutex> lock(queue_mutexes_[worker_id]);
            queue_conditions_[worker_id].wait(lock, [this, worker_id] {
                return !worker_queues_[worker_id].empty() || !workers_running_.load();
            });
            
            if (!workers_running_.load()) break;
            
            if (!worker_queues_[worker_id].empty()) {
                work_item = std::move(worker_queues_[worker_id].front());
                worker_queues_[worker_id].pop();
            }
        }
        
        if (work_item) {
            // Traitement séquentiel par ce worker
            HighResTimer timer;
            
            try {
                FilterResult result = ProcessPacketSequential(work_item->packet, worker_id);
                double processing_time = timer.ElapsedMilliseconds();
                
                UpdateWorkerStats(worker_id, processing_time);
                work_item->callback(result);
                
            } catch (const std::exception& e) {
                LOG_DEBUG(true, "Worker " + std::to_string(worker_id) + " error: " + e.what());
                
                FilterResult error_result;
                error_result.action = RuleAction::ACCEPT;
                error_result.rule_id = "worker_error";
                error_result.matched_layer = RuleLayer::L3;
                error_result.decision_time_ms = timer.ElapsedMilliseconds();
                error_result.early_termination = false;
                
                work_item->callback(error_result);
            }
        }
    }
    
    LOG_DEBUG(true, "Worker " + std::to_string(worker_id) + " stopped");
}

FilterResult HybridEngine::ProcessPacketSequential(const PacketData& packet, size_t worker_id) {
    HighResTimer timer;
    
    // Chaque worker fait du séquentiel L3→L4→L7 avec son propre TCP reassembler
    PacketData enriched_packet = packet;
    
    // TCP Reassembly si nécessaire (HTTP sur ports 80,443,8080...)
    if (packet.protocol == 6 && // TCP
        (packet.dst_port == 80 || packet.dst_port == 443 || 
         packet.dst_port == 8080 || packet.dst_port == 8443)) {
        
        // Utiliser le reassembler de ce worker (pas de locks)
        auto http_data = worker_reassemblers_[worker_id]->ProcessPacket(reinterpret_cast<unsigned char*>(&enriched_packet), sizeof(enriched_packet), enriched_packet);
        if (http_data) {
            enriched_packet.http_method = http_data->method;
            enriched_packet.http_uri = http_data->uri;
            enriched_packet.http_headers = http_data->headers;
            enriched_packet.http_payload = http_data->payload;
            enriched_packet.user_agent = http_data->user_agent;
            enriched_packet.host = http_data->host;
            enriched_packet.is_reassembled = true;
        }
    }
    
    FilterResult result;
    result.action = RuleAction::ACCEPT;
    result.rule_id = "default";
    result.matched_layer = RuleLayer::L7;
    result.early_termination = false;
    
    // L3 evaluation FIRST - STRICT SEQUENTIAL PER WORKER
    auto l3_result = EvaluateLayer(RuleLayer::L3, enriched_packet);
    if (l3_result.action == RuleAction::DROP) {
        result = l3_result;
        result.early_termination = true;
        stats_->l3_drops.fetch_add(1, std::memory_order_relaxed);
        goto finalize_worker;
    }
    
    // L4 evaluation - STRICT SEQUENTIAL
    auto l4_result = EvaluateLayer(RuleLayer::L4, enriched_packet);
    if (l4_result.action == RuleAction::DROP) {
        result = l4_result;
        result.early_termination = true;
        stats_->l4_drops.fetch_add(1, std::memory_order_relaxed);
        goto finalize_worker;
    }
    
    // L7 evaluation - STRICT SEQUENTIAL
    auto l7_result = EvaluateLayer(RuleLayer::L7, enriched_packet);
    if (l7_result.action == RuleAction::DROP) {
        result = l7_result;
        result.early_termination = true;
        stats_->l7_drops.fetch_add(1, std::memory_order_relaxed);
        goto finalize_worker;
    }
    
    // Tous layers passed
    stats_->accepted_packets.fetch_add(1, std::memory_order_relaxed);
    
finalize_worker:
    result.decision_time_ms = timer.ElapsedMilliseconds();
    stats_->total_decision_time.fetch_add(result.decision_time_ms, std::memory_order_relaxed);
    stats_->total_packets.fetch_add(1, std::memory_order_relaxed);
    
    if (result.action == RuleAction::DROP) {
        stats_->dropped_packets.fetch_add(1, std::memory_order_relaxed);
        stats_->UpdateRuleMatch(result.rule_id);
    }
    
    return result;
}

bool HybridEngine::EnqueueWork(size_t worker_id, std::unique_ptr<WorkItem> work) {
    std::lock_guard<std::mutex> lock(queue_mutexes_[worker_id]);
    
    if (worker_queues_[worker_id].size() >= MAX_QUEUE_SIZE) {
        queue_full_drops_.fetch_add(1, std::memory_order_relaxed);
        return false; // Queue pleine
    }
    
    worker_queues_[worker_id].push(std::move(work));
    queue_conditions_[worker_id].notify_one();
    
    return true;
}

void HybridEngine::UpdateWorkerStats(size_t worker_id, double processing_time) {
    auto current_count = worker_packet_counts_[worker_id].fetch_add(1, std::memory_order_relaxed);
    
    // Update running average
    double current_avg = worker_avg_times_[worker_id].load();
    double new_avg = ((current_avg * current_count) + processing_time) / (current_count + 1);
    worker_avg_times_[worker_id].store(new_avg);
}

void HybridEngine::SetWorkerAffinity(size_t worker_id) {
    #ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    
    auto cores = std::thread::hardware_concurrency();
    if (cores > 0) {
        size_t target_core = worker_id % cores;
        CPU_SET(target_core, &cpuset);
        
        int rc = pthread_setaffinity_np(worker_threads_[worker_id].native_handle(), 
                                       sizeof(cpu_set_t), &cpuset);
        if (rc == 0) {
            LOG_DEBUG(true, "Worker " + std::to_string(worker_id) + 
                           " bound to CPU core " + std::to_string(target_core));
        }
    }
    #endif
}

void HybridEngine::ShutdownWorkers() {
    workers_running_.store(false);
    
    // Wake up all workers
    for (size_t i = 0; i < num_workers_; ++i) {
        queue_conditions_[i].notify_all();
    }
    
    // Wait for all workers to finish
    for (auto& worker : worker_threads_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    worker_threads_.clear();
    
    // Clear remaining queues
    for (size_t i = 0; i < num_workers_; ++i) {
        std::lock_guard<std::mutex> lock(queue_mutexes_[i]);
        while (!worker_queues_[i].empty()) {
            worker_queues_[i].pop();
        }
    }
    
    std::cout << "✅ All workers stopped and cleaned up" << std::endl;
}

size_t HybridEngine::GetOptimalWorkerCount() const {
    auto cores = std::thread::hardware_concurrency();
    if (cores <= 2) return 2;
    if (cores <= 4) return cores;
    return cores - 1; // Leave one core for main thread
}

void HybridEngine::PrintPerformanceStats() const {
    RuleEngine::PrintPerformanceStats();
    
    std::cout << "\n🔥 Hybrid Multi-Worker Performance:" << std::endl;
    std::cout << "   Workers: " << num_workers_ << std::endl;
    std::cout << "   Dispatched packets: " << dispatched_packets_.load() << std::endl;
    std::cout << "   Queue full drops: " << queue_full_drops_.load() << std::endl;
    
    // Per-worker stats
    std::cout << "   Per-worker statistics:" << std::endl;
    for (size_t i = 0; i < num_workers_; ++i) {
        auto count = worker_packet_counts_[i].load();
        auto avg_time = worker_avg_times_[i].load();
        std::cout << "     Worker " << i << ": " << count 
                  << " packets, " << std::fixed << std::setprecision(3) 
                  << avg_time << "ms avg" << std::endl;
    }
    
    // Load balancing analysis
    if (num_workers_ > 1) {
        std::vector<uint64_t> counts;
        for (size_t i = 0; i < num_workers_; ++i) {
            counts.push_back(worker_packet_counts_[i].load());
        }
        
        auto min_count = *std::min_element(counts.begin(), counts.end());
        auto max_count = *std::max_element(counts.begin(), counts.end());
        
        double balance_ratio = min_count > 0 ? (double)max_count / min_count : 0.0;
        std::cout << "   Load balance ratio: " << std::fixed << std::setprecision(2) 
                  << balance_ratio << " (closer to 1.0 = better load distribution)" << std::endl;
    }
}