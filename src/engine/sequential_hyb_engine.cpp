#include "sequential_hyb_engine.h"
#include "../utils.h"

#include <iostream>
#include <algorithm>
#include <future>
#include <iomanip>

SequentialHybEngine::SequentialHybEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                                        size_t num_rule_workers)
    : RuleEngine(rules, FilterMode::SEQUENTIAL_HYB) {
    
    if (num_rule_workers == 0) {
        num_rule_workers_ = GetOptimalRuleWorkerCount();
    } else {
        num_rule_workers_ = num_rule_workers;
    }
    
    std::cout << "🔧 Sequential-Hybrid Engine initialized:" << std::endl;
    std::cout << "   Rule workers: " << num_rule_workers_ << std::endl;
    std::cout << "   Mode: Single packet stream + parallel rule evaluation" << std::endl;
}

bool SequentialHybEngine::Initialize() {
    std::cout << "✅ Sequential-Hybrid Engine ready with " << num_rule_workers_ 
              << " rule evaluation workers" << std::endl;
    return true;
}

void SequentialHybEngine::Shutdown() {
    std::cout << "🛑 Sequential-Hybrid Engine shutdown" << std::endl;
}

FilterResult SequentialHybEngine::FilterPacket(const PacketData& packet) {
    return EvaluateSequentialHyb(packet);
}

FilterResult SequentialHybEngine::EvaluateSequentialHyb(const PacketData& packet) {
    HighResTimer timer;

    stats_->total_packets.fetch_add(1, std::memory_order_relaxed);

    // Check cache first
    size_t packet_hash = HashPacketData(packet);
    FilterResult cached_result;
    if (CheckCache(packet_hash, cached_result)) {
        stats_->cache_hits.fetch_add(1, std::memory_order_relaxed);
        return cached_result;
    }

    FilterResult result;
    result.action = RuleAction::ACCEPT;
    result.rule_id = "default";
    result.matched_layer = RuleLayer::L7;
    result.early_termination = false;

    // L3 evaluation with rule parallelization
    auto l3_result = EvaluateLayerParallel(RuleLayer::L3, packet);
    if (l3_result.action == RuleAction::DROP) {
        result = l3_result;
        result.early_termination = true;
        stats_->l3_drops.fetch_add(1, std::memory_order_relaxed);
    } else {
        // L4 evaluation with rule parallelization
        auto l4_result = EvaluateLayerParallel(RuleLayer::L4, packet);
        if (l4_result.action == RuleAction::DROP) {
            result = l4_result;
            result.early_termination = true;
            stats_->l4_drops.fetch_add(1, std::memory_order_relaxed);
        } else {
            // L7 evaluation with rule parallelization
            auto l7_result = EvaluateLayerParallel(RuleLayer::L7, packet);
            if (l7_result.action == RuleAction::DROP) {
                result = l7_result;
                result.early_termination = true;
                stats_->l7_drops.fetch_add(1, std::memory_order_relaxed);
            } else {
                stats_->accepted_packets.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    result.decision_time_ms = timer.ElapsedMilliseconds();
    stats_->total_decision_time.fetch_add(result.decision_time_ms, std::memory_order_relaxed);

    if (result.action == RuleAction::DROP) {
        stats_->dropped_packets.fetch_add(1, std::memory_order_relaxed);
        stats_->UpdateRuleMatch(result.rule_id);
    }

    CacheResult(packet_hash, result);
    return result;
}

FilterResult SequentialHybEngine::EvaluateLayerParallel(RuleLayer layer, const PacketData& packet) {
    HighResTimer parallel_timer;
    
    const auto& rules = rules_by_layer_[layer];
    
    // If too few rules, use sequential to avoid parallelization overhead
    if (rules.size() <= 4) {
        sequential_fallbacks_.fetch_add(1, std::memory_order_relaxed);
        return EvaluateLayerSequential(layer, packet);
    }
    
    parallel_evaluations_.fetch_add(1, std::memory_order_relaxed);
    
    // Split rules among workers
    size_t chunk_size = std::max(1ul, rules.size() / num_rule_workers_);
    std::vector<std::future<FilterResult>> futures;
    
    for (size_t i = 0; i < rules.size(); i += chunk_size) {
        size_t end = std::min(i + chunk_size, rules.size());
        
        // Create a sub-vector of rules for this chunk
        std::vector<std::reference_wrapper<const std::unique_ptr<Rule>>> rule_chunk;
        for (size_t j = i; j < end; ++j) {
            rule_chunk.push_back(std::cref(rules[j]));
        }
        
        futures.push_back(std::async(std::launch::async, 
            [this, &rule_chunk, &packet, layer]() -> FilterResult {
                FilterResult chunk_result;
                chunk_result.action = RuleAction::ACCEPT;
                chunk_result.matched_layer = layer;
                
                for (const auto& rule_ref : rule_chunk) {
                    if (EvaluateRule(*rule_ref.get(), packet)) {
                        chunk_result.action = rule_ref.get()->action;
                        chunk_result.rule_id = rule_ref.get()->id;
                        return chunk_result;
                    }
                }
                return chunk_result;
            }));
    }
    
    // Wait for first DROP or all ACCEPT
    for (auto& future : futures) {
        try {
            auto result = future.get();
            if (result.action == RuleAction::DROP) {
                // Cancel remaining futures (best effort)
                // Note: std::async tasks cannot be easily cancelled
                
                double overhead = parallel_timer.ElapsedMilliseconds();
                parallel_overhead_.fetch_add(overhead, std::memory_order_relaxed);
                
                return result;
            }
        } catch (const std::exception& e) {
            LOG_DEBUG(true, "Rule evaluation error: " + std::string(e.what()));
            continue;
        }
    }
    
    // All rules returned ACCEPT
    FilterResult accept_result;
    accept_result.action = RuleAction::ACCEPT;
    accept_result.matched_layer = layer;
    
    double overhead = parallel_timer.ElapsedMilliseconds();
    parallel_overhead_.fetch_add(overhead, std::memory_order_relaxed);
    
    return accept_result;
}

FilterResult SequentialHybEngine::EvaluateLayerSequential(RuleLayer layer, const PacketData& packet) {
    FilterResult result;
    result.action = RuleAction::ACCEPT;
    result.matched_layer = layer;
    
    const auto& rules = rules_by_layer_[layer];
    for (const auto& rule : rules) {
        if (EvaluateRule(*rule, packet)) {
            result.action = rule->action;
            result.rule_id = rule->id;
            return result;
        }
    }
    
    return result;
}

void SequentialHybEngine::PrintPerformanceStats() const {
    RuleEngine::PrintPerformanceStats();
    
    std::cout << "\n🔀 Sequential-Hybrid Engine Rule Parallelization Stats:" << std::endl;
    std::cout << "   Rule workers: " << num_rule_workers_ << std::endl;
    
    auto parallel_evals = parallel_evaluations_.load();
    auto sequential_fallbacks = sequential_fallbacks_.load();
    auto total_evals = parallel_evals + sequential_fallbacks;
    
    if (total_evals > 0) {
        double parallel_rate = (static_cast<double>(parallel_evals) / total_evals) * 100.0;
        std::cout << "   Parallel evaluations: " << parallel_evals 
                  << " (" << std::fixed << std::setprecision(1) << parallel_rate << "%)" << std::endl;
        std::cout << "   Sequential fallbacks: " << sequential_fallbacks << std::endl;
        
        if (parallel_evals > 0) {
            double avg_overhead = parallel_overhead_.load() / parallel_evals;
            std::cout << "   Avg parallel overhead: " << std::fixed << std::setprecision(3) 
                      << avg_overhead << " ms" << std::endl;
        }
    }
}

size_t SequentialHybEngine::GetOptimalRuleWorkerCount() const {
    auto cores = std::thread::hardware_concurrency();
    if (cores <= 2) return 2;
    if (cores <= 4) return cores / 2; // Use half the cores for rule evaluation
    return 4; // Cap at 4 rule workers to avoid too much overhead
}