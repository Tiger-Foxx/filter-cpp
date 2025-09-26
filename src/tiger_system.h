#ifndef TIGER_SYSTEM_H
#define TIGER_SYSTEM_H

#include <string>
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <signal.h>

// Forward declarations
class RuleEngine;
class PacketHandler;
class MetricsCollector;

enum class FilterMode {
    SEQUENTIAL,
    HYBRID,
    SEQUENTIAL_HYB
};

class TigerFoxSystem {
private:
    FilterMode mode_;
    int queue_num_;
    std::string rules_file_;
    bool debug_mode_;
    bool running_;
    
    std::unique_ptr<RuleEngine> rule_engine_;
    std::unique_ptr<PacketHandler> packet_handler_;
    std::unique_ptr<MetricsCollector> metrics_;
    
    // Signal handling
    static std::atomic<bool> shutdown_requested_;
    static TigerFoxSystem* instance_;
    
    // Performance tracking
    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> dropped_packets_{0};
    std::atomic<uint64_t> accepted_packets_{0};
    
    // System management
    pid_t process_id_;
    bool iptables_rule_added_;
    
public:
    explicit TigerFoxSystem(FilterMode mode = FilterMode::SEQUENTIAL, 
                           int queue_num = 0,
                           const std::string& rules_file = "rules/tiger_rules.json",
                           bool debug = false);
    
    ~TigerFoxSystem();
    
    // Core functionality
    bool Initialize();
    void Start();
    void Stop();
    void Shutdown();
    
    // Configuration
    void SetMode(FilterMode mode) { mode_ = mode; }
    void SetQueueNumber(int queue_num) { queue_num_ = queue_num; }
    void SetRulesFile(const std::string& file) { rules_file_ = file; }
    void SetDebugMode(bool debug) { debug_mode_ = debug; }
    
    // Statistics
    void PrintStats() const;
    void PrintFinalStats() const;
    
    // Process management
    pid_t GetPID() const { return process_id_; }
    void DisplayPID() const;
    
    // Signal handlers
    static void SignalHandler(int signal);
    static void SetupSignalHandlers();
    
private:
    bool SetupIptablesRules();
    void CleanupIptablesRules();
    bool CheckRootPrivileges() const;
    void EnableIPForwarding();
    
    // Statistics update (thread-safe)
    void UpdatePacketStats(bool dropped);
};

#endif // TIGER_SYSTEM_H