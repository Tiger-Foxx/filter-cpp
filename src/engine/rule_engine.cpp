#include "rule_engine.h"
#include "../utils.h"

#include <iostream>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>

// Rule destructor - cleanup PCRE2 patterns
Rule::~Rule() {
    for (auto* pattern : compiled_patterns) {
        if (pattern) {
            pcre2_code_free(pattern);
        }
    }
}

void Rule::CompilePatterns() {
    compiled_patterns.clear();
    
    if (type == RuleType::HTTP_URI_REGEX || 
        type == RuleType::HTTP_PAYLOAD_REGEX) {
        
        for (const auto& pattern : values) {
            int error_code;
            PCRE2_SIZE error_offset;
            
            auto* compiled = pcre2_compile(
                (PCRE2_SPTR)pattern.c_str(),
                PCRE2_ZERO_TERMINATED,
                PCRE2_CASELESS | PCRE2_MULTILINE,
                &error_code,
                &error_offset,
                nullptr
            );
            
            if (compiled) {
                compiled_patterns.push_back(compiled);
            } else {
                std::cerr << "PCRE2 compilation error for pattern: " << pattern << std::endl;
            }
        }
    }
}

void Rule::CompileIPRanges() {
    compiled_ip_ranges.clear();
    
    if (type == RuleType::IP_SRC_IN || type == RuleType::IP_DST_IN) {
        for (const auto& value : values) {
            auto range = std::make_pair(0u, 0u);
            
            if (value.find('/') != std::string::npos) {
                // CIDR notation
                auto parts = StringUtils::Split(value, '/');
                if (parts.size() == 2) {
                    uint32_t ip = inet_addr(parts[0].c_str());
                    int prefix = std::stoi(parts[1]);
                    uint32_t mask = 0xFFFFFFFF << (32 - prefix);
                    
                    range.first = ntohl(ip) & ntohl(mask);
                    range.second = range.first | (~ntohl(mask));
                }
            } else {
                // Single IP
                uint32_t ip = ntohl(inet_addr(value.c_str()));
                range.first = ip;
                range.second = ip;
            }
            
            compiled_ip_ranges.push_back(range);
        }
    }
}

// EngineStats implementation
void EngineStats::UpdateRuleMatch(const std::string& rule_id) {
    std::lock_guard<std::mutex> lock(rule_matches_mutex);
    rule_matches[rule_id]++;
}

double EngineStats::GetAverageDecisionTime() const {
    auto total = total_packets.load();
    return total > 0 ? total_decision_time.load() / total : 0.0;
}

// RuleEngine base class implementation
RuleEngine::RuleEngine(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules,
                       FilterMode mode) 
    : mode_(mode), stats_(std::make_unique<EngineStats>()) {
    
    // Move rules to internal storage with compilation
    for (const auto& [layer, layer_rules] : rules) {
        for (const auto& rule : layer_rules) {
            auto rule_copy = std::make_unique<Rule>(*rule);
            rule_copy->CompilePatterns();
            rule_copy->CompileIPRanges();
            rules_by_layer_[layer].push_back(std::move(rule_copy));
        }
    }
    
    std::cout << "🔧 Base RuleEngine initialized with " << rules.size() << " layers" << std::endl;
}

RuleEngine::~RuleEngine() {
    // Cleanup handled by unique_ptr and Rule destructors
}

void RuleEngine::PrintPerformanceStats() const {
    auto total = stats_->total_packets.load();
    if (total == 0) return;
    
    std::cout << "\n📊 Rule Engine Base Performance Stats:" << std::endl;
    std::cout << "   Mode: " << (mode_ == FilterMode::SEQUENTIAL ? "SEQUENTIAL" :
                                 mode_ == FilterMode::HYBRID ? "HYBRID" : "SEQUENTIAL-HYB") << std::endl;
    std::cout << "   Total packets: " << total << std::endl;
    std::cout << "   Dropped: " << stats_->dropped_packets.load() << std::endl;
    std::cout << "   Accepted: " << stats_->accepted_packets.load() << std::endl;
    std::cout << "   Avg decision time: " << stats_->GetAverageDecisionTime() << " ms" << std::endl;
    std::cout << "   Cache hits: " << stats_->cache_hits.load() << std::endl;
    
    std::cout << "   Layer breakdown:" << std::endl;
    std::cout << "     L3 drops: " << stats_->l3_drops.load() << std::endl;
    std::cout << "     L4 drops: " << stats_->l4_drops.load() << std::endl;
    std::cout << "     L7 drops: " << stats_->l7_drops.load() << std::endl;
    
    // Top matched rules
    {
        std::lock_guard<std::mutex> lock(stats_->rule_matches_mutex);
        if (!stats_->rule_matches.empty()) {
            std::cout << "   Top matched rules:" << std::endl;
            
            std::vector<std::pair<std::string, uint64_t>> sorted_rules(
                stats_->rule_matches.begin(), stats_->rule_matches.end()
            );
            
            std::sort(sorted_rules.begin(), sorted_rules.end(),
                     [](const auto& a, const auto& b) { return a.second > b.second; });
            
            for (size_t i = 0; i < std::min(5ul, sorted_rules.size()); ++i) {
                std::cout << "     " << sorted_rules[i].first 
                          << ": " << sorted_rules[i].second << " matches" << std::endl;
            }
        }
    }
}

void RuleEngine::ResetStats() {
    stats_->total_packets.store(0);
    stats_->dropped_packets.store(0);
    stats_->accepted_packets.store(0);
    stats_->l3_drops.store(0);
    stats_->l4_drops.store(0);
    stats_->l7_drops.store(0);
    stats_->total_decision_time.store(0.0);
    stats_->cache_hits.store(0);
    
    {
        std::lock_guard<std::mutex> lock(stats_->rule_matches_mutex);
        stats_->rule_matches.clear();
    }
    
    CleanupCache();
}

// Shared rule evaluation methods
FilterResult RuleEngine::EvaluateLayer(RuleLayer layer, const PacketData& packet) {
    FilterResult result;
    result.action = RuleAction::ACCEPT;
    result.matched_layer = layer;
    result.rule_id = "none";
    result.early_termination = false;
    result.decision_time_ms = 0.0;
    
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

bool RuleEngine::EvaluateRule(const Rule& rule, const PacketData& packet) {
    switch (rule.layer) {
        case RuleLayer::L3:
            return EvaluateL3Rule(rule, packet);
        case RuleLayer::L4:
            return EvaluateL4Rule(rule, packet);
        case RuleLayer::L7:
            return EvaluateL7Rule(rule, packet);
        default:
            return false;
    }
}

bool RuleEngine::EvaluateL3Rule(const Rule& rule, const PacketData& packet) {
    switch (rule.type) {
        case RuleType::IP_SRC_IN:
            return IsIPInRange(packet.src_ip, rule.compiled_ip_ranges);
            
        case RuleType::IP_DST_IN:
            return IsIPInRange(packet.dst_ip, rule.compiled_ip_ranges);
            
        case RuleType::IP_SRC_COUNTRY:
            // Simplified geo-IP check (would need GeoIP database in real implementation)
            for (const auto& country : rule.values) {
                if (country == "CN" && (packet.src_ip.rfind("220.", 0) == 0 || packet.src_ip.rfind("221.", 0) == 0)) return true;
                if (country == "RU" && (packet.src_ip.rfind("94.", 0) == 0 || packet.src_ip.rfind("95.", 0) == 0)) return true;
                if (country == "IR" && packet.src_ip.rfind("5.", 0) == 0) return true;
                if (country == "KP" && packet.src_ip.rfind("175.45.", 0) == 0) return true;
            }
            return false;
            
        default:
            return false;
    }
}

bool RuleEngine::EvaluateL4Rule(const Rule& rule, const PacketData& packet) {
    switch (rule.type) {
        case RuleType::TCP_DST_PORT:
            if (packet.protocol != 6) return false; // TCP = 6
            for (const auto& port_str : rule.values) {
                if (packet.dst_port == static_cast<uint16_t>(std::stoi(port_str))) {
                    return true;
                }
            }
            return false;
            
        case RuleType::TCP_DST_PORT_NOT_IN:
            if (packet.protocol != 6) return false;
            for (const auto& port_str : rule.values) {
                if (packet.dst_port == static_cast<uint16_t>(std::stoi(port_str))) {
                    return false;
                }
            }
            return true;
            
        case RuleType::UDP_DST_PORT:
            if (packet.protocol != 17) return false; // UDP = 17
            for (const auto& port_str : rule.values) {
                if (packet.dst_port == static_cast<uint16_t>(std::stoi(port_str))) {
                    return true;
                }
            }
            return false;
            
        case RuleType::TCP_FLAGS:
            if (packet.protocol != 6) return false;
            for (const auto& flag : rule.values) {
                if (packet.tcp_flags.find(flag) != std::string::npos) {
                    return true;
                }
            }
            return false;
            
        default:
            return false;
    }
}

bool RuleEngine::EvaluateL7Rule(const Rule& rule, const PacketData& packet) {
    switch (rule.type) {
        case RuleType::HTTP_URI_REGEX:
            return MatchRegexPatterns(rule.compiled_patterns, packet.http_uri);
            
        case RuleType::HTTP_HEADER_CONTAINS: {
            auto field_lower = StringUtils::ToLower(rule.field);
            auto it = packet.http_headers.find(field_lower);
            if (it != packet.http_headers.end()) {
                auto header_value_lower = StringUtils::ToLower(it->second);
                for (const auto& value : rule.values) {
                    if (header_value_lower.find(StringUtils::ToLower(value)) != std::string::npos) {
                        return true;
                    }
                }
            }
            return false;
        }
            
        case RuleType::HTTP_METHOD:
            for (const auto& method : rule.values) {
                if (StringUtils::ToLower(packet.http_method) == StringUtils::ToLower(method)) {
                    return true;
                }
            }
            return false;
            
        case RuleType::HTTP_PAYLOAD_REGEX:
            return MatchRegexPatterns(rule.compiled_patterns, packet.http_payload);
            
        case RuleType::DNS_QUERY_CONTAINS:
            for (const auto& domain : rule.values) {
                if (packet.dns_query_name.find(StringUtils::ToLower(domain)) != std::string::npos) {
                    return true;
                }
            }
            return false;
            
        default:
            return false;
    }
}

// Optimization helpers
bool RuleEngine::IsIPInRange(const std::string& ip, const std::vector<std::pair<uint32_t, uint32_t>>& ranges) const {
    uint32_t ip_uint = IPv4ToUint32(ip);
    if (ip_uint == 0) return false;
    
    for (const auto& range : ranges) {
        if (ip_uint >= range.first && ip_uint <= range.second) {
            return true;
        }
    }
    return false;
}

uint32_t RuleEngine::IPv4ToUint32(const std::string& ip) const {
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1) {
        return ntohl(sa.sin_addr.s_addr);
    }
    return 0;
}

bool RuleEngine::MatchRegexPatterns(const std::vector<pcre2_code*>& patterns, const std::string& text) const {
    if (patterns.empty() || text.empty()) return false;
    
    pcre2_match_data* match_data = pcre2_match_data_create_from_pattern(patterns[0], nullptr);
    
    for (auto* pattern : patterns) {
        int rc = pcre2_match(
            pattern,
            (PCRE2_SPTR)text.c_str(),
            text.length(),
            0,
            0,
            match_data,
            nullptr
        );
        
        if (rc > 0) {
            pcre2_match_data_free(match_data);
            return true;
        }
    }
    
    pcre2_match_data_free(match_data);
    return false;
}

size_t RuleEngine::HashPacketData(const PacketData& packet) const {
    // Simple hash for caching
    std::hash<std::string> hasher;
    return hasher(packet.src_ip + packet.dst_ip + std::to_string(packet.src_port) + 
                 std::to_string(packet.dst_port) + packet.http_uri);
}

bool RuleEngine::CheckCache(size_t packet_hash, FilterResult& result) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = decision_cache_.find(packet_hash);
    if (it != decision_cache_.end()) {
        result = it->second;
        return true;
    }
    return false;
}

void RuleEngine::CacheResult(size_t packet_hash, const FilterResult& result) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    if (decision_cache_.size() >= MAX_CACHE_SIZE) {
        // Simple LRU: clear half the cache
        auto it = decision_cache_.begin();
        std::advance(it, MAX_CACHE_SIZE / 2);
        decision_cache_.erase(decision_cache_.begin(), it);
    }
    
    decision_cache_[packet_hash] = result;
}

void RuleEngine::CleanupCache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    decision_cache_.clear();
}