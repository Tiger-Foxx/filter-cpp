#ifndef SEQUENTIAL_HYB_ENGINE_H
#define SEQUENTIAL_HYB_ENGINE_H

#include "rule_engine.h"
#include <memory>
#include <vector>
#include <future>
#include <thread>

// Sequential-Hybrid: Single packet worker + parallel rule evaluation
class SequentialHybEngine : public RuleEngine {
private:
    // Rule parallelization (not packet parallelization)
    std::vector<std::thread> rule_threads_;
    size_t num_rule_workers_;
    
    // Performance tracking for rule parallelization
    std::atomic<uint64_t> parallel_evaluations_{0};
    std::atomic<uint64_t> sequential_fallbacks_{0};
    std::atomic<double> parallel_overhead_{0.0};

public:
    explicit SequentialHybEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                                size_t num_rule_workers = 0);
    
    ~SequentialHybEngine() override = default;
    
    bool Initialize() override;
    void Shutdown() override;
    
    FilterResult FilterPacket(const PacketData& packet) override;
    
    void PrintPerformanceStats() const override;

private:
    // Sequential-Hyb specific implementation
    FilterResult EvaluateSequentialHyb(const PacketData& packet);
    FilterResult EvaluateLayerParallel(RuleLayer layer, const PacketData& packet);
    FilterResult EvaluateLayerSequential(RuleLayer layer, const PacketData& packet);
    
    // Rule chunk evaluation for parallel processing
    FilterResult EvaluateRuleChunk(const std::vector<std::unique_ptr<Rule>>& rules, 
                                  const PacketData& packet, RuleLayer layer);
    
    size_t GetOptimalRuleWorkerCount() const;
};

#endif // SEQUENTIAL_HYB_ENGINE_H