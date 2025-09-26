#include "tiger_system.h"
#include "engine/rule_engine.h"
#include "engine/sequential_engine.h"
#include "engine/sequential_hyb_engine.h"
#include "engine/hybrid_engine.h"
#include "handlers/packet_handler.h"
#include "loaders/rule_loader.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <chrono>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <csignal>

// Static member initialization
std::atomic<bool> TigerFoxSystem::shutdown_requested_{false};
TigerFoxSystem* TigerFoxSystem::instance_ = nullptr;

TigerFoxSystem::TigerFoxSystem(FilterMode mode, int queue_num, 
                               const std::string& rules_file, bool debug)
    : mode_(mode), queue_num_(queue_num), rules_file_(rules_file), 
      debug_mode_(debug), running_(false), process_id_(getpid()),
      iptables_rule_added_(false) {
    
    instance_ = this;
    SetupSignalHandlers();
    
    std::cout << "🦊 TIGER-FOX C++ Network Filtering System Initialized" << std::endl;
    std::cout << "   Mode: " << (mode_ == FilterMode::SEQUENTIAL ? "SEQUENTIAL" :
                                mode_ == FilterMode::HYBRID ? "HYBRID" : "SEQUENTIAL-HYB") << std::endl;
    std::cout << "   Queue: " << queue_num_ << std::endl;
    std::cout << "   Rules: " << rules_file_ << std::endl;
    std::cout << "   PID: " << process_id_ << std::endl;
}

TigerFoxSystem::~TigerFoxSystem() {
    Shutdown();
}

bool TigerFoxSystem::Initialize() {
    std::cout << "\n🔧 Initializing Tiger-Fox System..." << std::endl;
    
    // Check root privileges
    if (!CheckRootPrivileges()) {
        std::cerr << "❌ Error: Tiger-Fox must be run as root for NFQUEUE access" << std::endl;
        std::cerr << "   Please run with: sudo ./tiger-fox" << std::endl;
        return false;
    }
    
    // Enable IP forwarding
    EnableIPForwarding();
    
    // Load rules
    std::cout << "📋 Loading rules from: " << rules_file_ << std::endl;
    RuleLoader loader;
    auto rules_by_layer = loader.LoadRules(rules_file_);
    
    if (rules_by_layer.empty()) {
        std::cerr << "❌ Error: Failed to load rules from " << rules_file_ << std::endl;
        return false;
    }
    
    // Display rule statistics
    size_t total_rules = 0;
    for (const auto& [layer, rules] : rules_by_layer) {
        std::cout << "   L" << static_cast<int>(layer) << " rules: " << rules.size() << std::endl;
        total_rules += rules.size();
    }
    std::cout << "   Total rules loaded: " << total_rules << std::endl;
    
    // Initialize rule engine based on mode
    switch (mode_) {
        case FilterMode::SEQUENTIAL:
            rule_engine_ = std::make_unique<SequentialEngine>(rules_by_layer);
            break;
        case FilterMode::SEQUENTIAL_HYB:
            rule_engine_ = std::make_unique<SequentialHybEngine>(rules_by_layer);
            break;
        case FilterMode::HYBRID:
            rule_engine_ = std::make_unique<HybridEngine>(rules_by_layer);
            break;
        default:
            std::cerr << "❌ Error: Unknown filter mode specified" << std::endl;
            return false;
    }
    if (!rule_engine_->Initialize()) {
        std::cerr << "❌ Error: Failed to initialize rule engine" << std::endl;
        return false;
    }
    
    // Initialize packet handler
    std::cout << "📦 Initializing Packet Handler..." << std::endl;
    packet_handler_ = std::make_unique<PacketHandler>(queue_num_, rule_engine_.get(), debug_mode_);
    if (!packet_handler_->Initialize()) {
        std::cerr << "❌ Error: Failed to initialize packet handler" << std::endl;
        return false;
    }
    
    // Setup iptables rules
    std::cout << "🔥 Setting up iptables FORWARD rules..." << std::endl;
    if (!SetupIptablesRules()) {
        std::cerr << "❌ Error: Failed to setup iptables rules" << std::endl;
        return false;
    }
    
    std::cout << "✅ Tiger-Fox System initialized successfully!" << std::endl;
    return true;
}

void TigerFoxSystem::Start() {
    if (running_) {
        std::cout << "⚠️  System already running" << std::endl;
        return;
    }
    
    std::cout << "\n🚀 Starting Tiger-Fox Network Filtering..." << std::endl;
    std::cout << "=" << std::string(60, '=') << std::endl;
    std::cout << "TIGER-FOX C++ HIGH-PERFORMANCE NETWORK FILTERING" << std::endl;
    std::cout << "=" << std::string(60, '=') << std::endl;
    std::cout << "Mode: " << (mode_ == FilterMode::SEQUENTIAL ? "SEQUENTIAL" :
                               mode_ == FilterMode::HYBRID ? "HYBRID MULTI-WORKER" : 
                               "SEQUENTIAL-HYBRID") << std::endl;
    std::cout << "Queue: " << queue_num_ << std::endl;
    std::cout << "PID: " << process_id_ << std::endl;
    std::cout << "Architecture: CloudLab inline filtering" << std::endl;
    std::cout << "Traffic flow: injector → filter → server" << std::endl;
    std::cout << "Ready for traffic analysis and filtering" << std::endl;
    std::cout << "Press Ctrl+C to stop and show statistics" << std::endl;
    std::cout << "=" << std::string(60, '=') << std::endl;
    
    running_ = true;
    
    // Start packet processing (blocking call)
    packet_handler_->Start([this](bool dropped) {
        UpdatePacketStats(dropped);
    });
}

void TigerFoxSystem::Stop() {
    if (!running_) return;
    
    std::cout << "\n🛑 Stopping Tiger-Fox System..." << std::endl;
    running_ = false;
    
    if (packet_handler_) {
        packet_handler_->Stop();
    }
    
    if (rule_engine_) {
        rule_engine_->Shutdown();
    }
    
    PrintFinalStats();
}

void TigerFoxSystem::Shutdown() {
    Stop();
    CleanupIptablesRules();
    std::cout << "🧹 Tiger-Fox System shut down complete" << std::endl;
}

bool TigerFoxSystem::SetupIptablesRules() {
    std::string cmd = "iptables -C FORWARD -j NFQUEUE --queue-num " + std::to_string(queue_num_) + " 2>/dev/null";
    
    // Check if rule already exists
    int result = system(cmd.c_str());
    if (result == 0) {
        std::cout << "   ✅ iptables FORWARD rule already exists for queue " << queue_num_ << std::endl;
        return true;
    }
    
    // Add the rule
    cmd = "iptables -I FORWARD -j NFQUEUE --queue-num " + std::to_string(queue_num_);
    result = system(cmd.c_str());
    
    if (result == 0) {
        iptables_rule_added_ = true;
        std::cout << "   ✅ iptables FORWARD rule added for queue " << queue_num_ << std::endl;
        return true;
    } else {
        std::cerr << "   ❌ Failed to add iptables rule (exit code: " << result << ")" << std::endl;
        return false;
    }
}

void TigerFoxSystem::CleanupIptablesRules() {
    if (!iptables_rule_added_) return;
    
    std::cout << "🧹 Cleaning up iptables rules..." << std::endl;
    std::string cmd = "iptables -D FORWARD -j NFQUEUE --queue-num " + std::to_string(queue_num_);
    int result = system(cmd.c_str());
    
    if (result == 0) {
        std::cout << "   ✅ iptables rule removed successfully" << std::endl;
    } else {
        std::cerr << "   ⚠️  Warning: Failed to remove iptables rule" << std::endl;
    }
    iptables_rule_added_ = false;
}

bool TigerFoxSystem::CheckRootPrivileges() const {
    return geteuid() == 0;
}

void TigerFoxSystem::EnableIPForwarding() {
    std::cout << "🌐 Enabling IP forwarding..." << std::endl;
    int result = system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1");
    if (result == 0) {
        std::cout << "   ✅ IP forwarding enabled" << std::endl;
    } else {
        std::cerr << "   ⚠️  Warning: Failed to enable IP forwarding" << std::endl;
    }
}

void TigerFoxSystem::UpdatePacketStats(bool dropped) {
    total_packets_.fetch_add(1, std::memory_order_relaxed);
    if (dropped) {
        dropped_packets_.fetch_add(1, std::memory_order_relaxed);
    } else {
        accepted_packets_.fetch_add(1, std::memory_order_relaxed);
    }
}

void TigerFoxSystem::PrintStats() const {
    auto total = total_packets_.load();
    auto dropped = dropped_packets_.load();
    auto accepted = accepted_packets_.load();
    
    if (total == 0) return;
    
    double drop_rate = (double)dropped / total * 100.0;
    
    std::cout << "\n📊 Current Statistics:" << std::endl;
    std::cout << "   Total packets: " << total << std::endl;
    std::cout << "   Dropped: " << dropped << " (" << std::fixed << std::setprecision(2) << drop_rate << "%)" << std::endl;
    std::cout << "   Accepted: " << accepted << std::endl;
}

void TigerFoxSystem::PrintFinalStats() const {
    auto total = total_packets_.load();
    auto dropped = dropped_packets_.load();
    auto accepted = accepted_packets_.load();
    
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "FINAL STATISTICS - TIGER-FOX C++ EXPERIMENT" << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "Mode: " << (mode_ == FilterMode::SEQUENTIAL ? "SEQUENTIAL" :
                               mode_ == FilterMode::HYBRID ? "HYBRID MULTI-WORKER" : 
                               "SEQUENTIAL-HYBRID") << std::endl;
    std::cout << "Total packets processed: " << total << std::endl;
    std::cout << "Packets dropped: " << dropped << std::endl;
    std::cout << "Packets accepted: " << accepted << std::endl;
    
    if (total > 0) {
        double drop_rate = (double)dropped / total * 100.0;
        std::cout << "Drop rate: " << std::fixed << std::setprecision(2) << drop_rate << "%" << std::endl;
    }
    
    if (rule_engine_) {
        rule_engine_->PrintPerformanceStats();
    }
    
    std::cout << std::string(70, '=') << std::endl;
}

void TigerFoxSystem::DisplayPID() const {
    std::cout << "🆔 Tiger-Fox PID: " << process_id_ << std::endl;
    std::cout << "   Kill with: sudo kill " << process_id_ << std::endl;
}

// Signal handling
void TigerFoxSystem::SignalHandler(int signal) {
    shutdown_requested_.store(true);
    std::cout << "\n🛑 Received signal " << signal << ", initiating shutdown..." << std::endl;
    
    if (instance_) {
        instance_->Stop();
    }
}

void TigerFoxSystem::SetupSignalHandlers() {
    signal(SIGINT, SignalHandler);   // Ctrl+C
    signal(SIGTERM, SignalHandler);  // Termination signal
    signal(SIGQUIT, SignalHandler);  // Quit signal
}