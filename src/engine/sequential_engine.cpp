#include "sequential_engine.h"
#include "../utils.h"

#include <iomanip>
#include <iostream>

SequentialEngine::SequentialEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules)
    : RuleEngine(rules, FilterMode::SEQUENTIAL) {
    
    std::cout << "🔧 Sequential Engine initialized" << std::endl;
}

bool SequentialEngine::Initialize() {
    std::cout << "✅ Sequential Engine ready" << std::endl;
    return true;
}

void SequentialEngine::Shutdown() {
    std::cout << "🛑 Sequential Engine shutdown" << std::endl;
}

FilterResult SequentialEngine::FilterPacket(const PacketData& packet) {
    return EvaluateSequential(packet);
}

FilterResult SequentialEngine::EvaluateSequential(const PacketData& packet) {
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

    // L3 evaluation first - STRICT ORDER
    HighResTimer l3_timer;
    auto l3_result = EvaluateLayer(RuleLayer::L3, packet);
    double l3_time = l3_timer.ElapsedMilliseconds();

    l3_evaluations_.fetch_add(1, std::memory_order_relaxed);
    l3_total_time_.fetch_add(l3_time, std::memory_order_relaxed);

    if (l3_result.action == RuleAction::DROP) {
        result = l3_result;
        result.early_termination = true;
        stats_->l3_drops.fetch_add(1, std::memory_order_relaxed);
    } else {
        // L4 evaluation - STRICT ORDER
        HighResTimer l4_timer;
        auto l4_result = EvaluateLayer(RuleLayer::L4, packet);
        double l4_time = l4_timer.ElapsedMilliseconds();

        l4_evaluations_.fetch_add(1, std::memory_order_relaxed);
        l4_total_time_.fetch_add(l4_time, std::memory_order_relaxed);

        if (l4_result.action == RuleAction::DROP) {
            result = l4_result;
            result.early_termination = true;
            stats_->l4_drops.fetch_add(1, std::memory_order_relaxed);
        } else {
            // L7 evaluation - STRICT ORDER
            HighResTimer l7_timer;
            auto l7_result = EvaluateLayer(RuleLayer::L7, packet);
            double l7_time = l7_timer.ElapsedMilliseconds();

            l7_evaluations_.fetch_add(1, std::memory_order_relaxed);
            l7_total_time_.fetch_add(l7_time, std::memory_order_relaxed);

            if (l7_result.action == RuleAction::DROP) {
                result = l7_result;
                result.early_termination = true;
                stats_->l7_drops.fetch_add(1, std::memory_order_relaxed);
            } else {
                // All layers passed
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

FilterResult SequentialEngine::EvaluateLayer(RuleLayer layer, const PacketData& packet) {
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

void SequentialEngine::PrintPerformanceStats() const {
    RuleEngine::PrintPerformanceStats();
    
    std::cout << "\n📊 Sequential Engine Layer Performance:" << std::endl;
    
    auto l3_evals = l3_evaluations_.load();
    auto l4_evals = l4_evaluations_.load();
    auto l7_evals = l7_evaluations_.load();
    
    if (l3_evals > 0) {
        double l3_avg = l3_total_time_.load() / l3_evals;
        std::cout << "   L3: " << l3_evals << " evaluations, " 
                  << std::fixed << std::setprecision(3) << l3_avg << " ms avg" << std::endl;
    }
    
    if (l4_evals > 0) {
        double l4_avg = l4_total_time_.load() / l4_evals;
        std::cout << "   L4: " << l4_evals << " evaluations, " 
                  << std::fixed << std::setprecision(3) << l4_avg << " ms avg" << std::endl;
    }
    
    if (l7_evals > 0) {
        double l7_avg = l7_total_time_.load() / l7_evals;
        std::cout << "   L7: " << l7_evals << " evaluations, " 
                  << std::fixed << std::setprecision(3) << l7_avg << " ms avg" << std::endl;
    }
}