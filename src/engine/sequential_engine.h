#ifndef SEQUENTIAL_ENGINE_H
#define SEQUENTIAL_ENGINE_H

#include "rule_engine.h"
#include <memory>

class SequentialEngine : public RuleEngine {
public:
    explicit SequentialEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules);
    
    ~SequentialEngine() override = default;
    
    bool Initialize() override;
    void Shutdown() override;
    
    FilterResult FilterPacket(const PacketData& packet) override;
    
    void PrintPerformanceStats() const override;

private:
    // Sequential-specific implementation
    FilterResult EvaluateSequential(const PacketData& packet);
    FilterResult EvaluateLayer(RuleLayer layer, const PacketData& packet);
    
    // Performance tracking
    std::atomic<uint64_t> l3_evaluations_{0};
    std::atomic<uint64_t> l4_evaluations_{0};
    std::atomic<uint64_t> l7_evaluations_{0};
    
    std::atomic<double> l3_total_time_{0.0};
    std::atomic<double> l4_total_time_{0.0};
    std::atomic<double> l7_total_time_{0.0};
};

#endif // SEQUENTIAL_ENGINE_H