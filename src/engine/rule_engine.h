#ifndef RULE_ENGINE_H  
#define RULE_ENGINE_H

#include <memory>
#include <vector>
#include <unordered_map>
#include <string>
#include <atomic>
#include <mutex>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

// Forward declarations
struct PacketData;

enum class FilterMode {
    SEQUENTIAL,        // Mode séquentiel : L3→L4→L7 strict
    HYBRID,           // Mode multi-worker avec hash dispatch
    SEQUENTIAL_HYB    // Mode séquentiel + parallélisme règles
};

enum class RuleAction {
    DROP,
    ACCEPT,
    REJECT
};

enum class RuleLayer {
    L3 = 3,
    L4 = 4, 
    L7 = 7
};

enum class RuleType {
    // L3 Rules
    IP_SRC_IN,
    IP_DST_IN,
    IP_SRC_COUNTRY,
    
    // L4 Rules  
    TCP_DST_PORT,
    TCP_DST_PORT_NOT_IN,
    UDP_DST_PORT,
    TCP_FLAGS,
    
    // L7 Rules
    HTTP_URI_REGEX,
    HTTP_HEADER_CONTAINS,
    HTTP_METHOD,
    HTTP_PAYLOAD_REGEX,
    DNS_QUERY_CONTAINS
};

struct Rule {
    std::string id;
    RuleLayer layer;
    RuleType type;
    RuleAction action;
    std::vector<std::string> values;
    std::string field; // Pour http_header_contains
    
    // Pre-compiled optimizations
    std::vector<pcre2_code*> compiled_patterns;
    std::vector<std::pair<uint32_t, uint32_t>> compiled_ip_ranges;
    
    Rule() = default;
    ~Rule();
    
    void CompilePatterns();
    void CompileIPRanges();
};

struct PacketData {
    // L3 Data
    std::string src_ip;
    std::string dst_ip;
    uint8_t protocol;
    uint16_t ip_length;
    
    // L4 Data  
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string tcp_flags;
    uint32_t seq_num = 0;
    uint32_t ack_num = 0;
    
    // L7 Data (HTTP)
    std::string http_method;
    std::string http_uri;
    std::string http_version;
    std::unordered_map<std::string, std::string> http_headers;
    std::string http_payload;
    std::string user_agent;
    std::string host;
    
    // DNS Data
    std::string dns_query_name;
    
    // Metadata
    size_t packet_size = 0;
    bool is_reassembled = false;
    uint64_t timestamp_ns = 0;
};

struct FilterResult {
    RuleAction action;
    std::string rule_id;
    RuleLayer matched_layer;
    double decision_time_ms;
    bool early_termination;
};

// Performance Statistics
struct EngineStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> accepted_packets{0};
    
    std::atomic<uint64_t> l3_drops{0};
    std::atomic<uint64_t> l4_drops{0};
    std::atomic<uint64_t> l7_drops{0};
    
    std::atomic<double> total_decision_time{0.0};
    std::atomic<uint64_t> cache_hits{0};
    
    std::unordered_map<std::string, uint64_t> rule_matches;
    mutable std::mutex rule_matches_mutex;
    
    void UpdateRuleMatch(const std::string& rule_id);
    double GetAverageDecisionTime() const;
};

// Base class for all rule engines
class RuleEngine {
protected:
    FilterMode mode_;
    std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> rules_by_layer_;
    
    // Performance tracking
    std::unique_ptr<EngineStats> stats_;
    
    // Optimizations
    mutable std::unordered_map<size_t, FilterResult> decision_cache_;
    mutable std::mutex cache_mutex_;
    static constexpr size_t MAX_CACHE_SIZE = 10000;
    
public:
    explicit RuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                       FilterMode mode);
    
    virtual ~RuleEngine();
    
    // Core interface - implemented by subclasses
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual FilterResult FilterPacket(const PacketData& packet) = 0;
    
    // Common functionality
    const EngineStats& GetStats() const { return *stats_; }
    virtual void PrintPerformanceStats() const;
    void ResetStats();
    
    FilterMode GetMode() const { return mode_; }

protected:
    // Shared rule evaluation methods
    FilterResult EvaluateLayer(RuleLayer layer, const PacketData& packet);
    bool EvaluateRule(const Rule& rule, const PacketData& packet);
    
    // Layer-specific evaluation
    bool EvaluateL3Rule(const Rule& rule, const PacketData& packet);
    bool EvaluateL4Rule(const Rule& rule, const PacketData& packet);  
    bool EvaluateL7Rule(const Rule& rule, const PacketData& packet);
    
    // Optimization helpers
    size_t HashPacketData(const PacketData& packet) const;
    bool CheckCache(size_t packet_hash, FilterResult& result) const;
    void CacheResult(size_t packet_hash, const FilterResult& result);
    void CleanupCache();
    
    // Utilities
    bool IsIPInRange(const std::string& ip, const std::vector<std::pair<uint32_t, uint32_t>>& ranges) const;
    uint32_t IPv4ToUint32(const std::string& ip) const;
    bool MatchRegexPatterns(const std::vector<pcre2_code*>& patterns, const std::string& text) const;
};

#endif // RULE_ENGINE_H