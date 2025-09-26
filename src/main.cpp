#include "tiger_system.h"
#include "utils.h"

#include <iostream>
#include <string>
#include <map>
#include <getopt.h>

void PrintUsage(const char* program_name) {
    std::cout << "\n🦊 Tiger-Fox C++ High-Performance Network Filtering" << std::endl;
    std::cout << "===============================================" << std::endl;
    std::cout << "Usage: " << program_name << " [OPTIONS]" << std::endl;
    std::cout << "\nModes:" << std::endl;
    std::cout << "  --sequential      Sequential mode (L3→L4→L7, single-threaded)" << std::endl;
    std::cout << "  --hybrid          Hybrid multi-worker mode (multiple threads)" << std::endl;
    std::cout << "  --sequential-hyb  Sequential-Hybrid mode (parallel rule checking)" << std::endl;
    std::cout << "\nOptions:" << std::endl;
    std::cout << "  -q, --queue NUM      NFQUEUE number (default: 0)" << std::endl;
    std::cout << "  -r, --rules FILE     Rules file path (default: rules/tiger_rules.json)" << std::endl;
    std::cout << "  -d, --debug          Enable debug mode" << std::endl;
    std::cout << "  -h, --help           Show this help message" << std::endl;
    std::cout << "  --pid                Display PID and exit" << std::endl;
    std::cout << "\nCloudLab Architecture:" << std::endl;
    std::cout << "  injector (10.10.1.10) → filter (10.10.1.1/10.10.2.1) → server (10.10.2.20)" << std::endl;
    std::cout << "\nThe filter machine will intercept ALL traffic flowing through it." << std::endl;
    std::cout << "\nExample usage:" << std::endl;
    std::cout << "  sudo ./tiger-fox --hybrid -q 0 -d" << std::endl;
    std::cout << "  sudo ./tiger-fox --sequential --rules my_rules.json" << std::endl;
    std::cout << "\n⚠️  Note: Must be run as root for NFQUEUE access" << std::endl;
}

int main(int argc, char* argv[]) {
    // Default configuration
    FilterMode mode = FilterMode::SEQUENTIAL;
    int queue_num = 0;
    std::string rules_file = "rules/tiger_rules.json";
    bool debug_mode = false;
    bool show_pid_only = false;
    
    // Command line options
    static struct option long_options[] = {
        {"sequential",     no_argument,       0, 's'},
        {"hybrid",         no_argument,       0, 'h'},
        {"sequential-hyb", no_argument,       0, 'y'},
        {"queue",          required_argument, 0, 'q'},
        {"rules",          required_argument, 0, 'r'},
        {"debug",          no_argument,       0, 'd'},
        {"help",           no_argument,       0, 'H'},
        {"pid",            no_argument,       0, 'p'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "shyq:r:dHp", long_options, &option_index)) != -1) {
        switch (c) {
            case 's':
                mode = FilterMode::SEQUENTIAL;
                break;
            case 'h':
                mode = FilterMode::HYBRID;
                break;
            case 'y':
                mode = FilterMode::SEQUENTIAL_HYB;
                break;
            case 'q':
                queue_num = std::stoi(optarg);
                break;
            case 'r':
                rules_file = optarg;
                break;
            case 'd':
                debug_mode = true;
                break;
            case 'H':
                PrintUsage(argv[0]);
                return 0;
            case 'p':
                show_pid_only = true;
                break;
            case '?':
                std::cerr << "❌ Unknown option. Use --help for usage information." << std::endl;
                return 1;
            default:
                PrintUsage(argv[0]);
                return 1;
        }
    }
    
    // Show PID and exit if requested
    if (show_pid_only) {
        std::cout << "Current PID: " << getpid() << std::endl;
        return 0;
    }
    
    // Create and initialize Tiger-Fox system
    try {
        TigerFoxSystem tiger_fox(mode, queue_num, rules_file, debug_mode);
        
        // Display PID for process management
        tiger_fox.DisplayPID();
        
        // Initialize the system
        if (!tiger_fox.Initialize()) {
            std::cerr << "❌ Failed to initialize Tiger-Fox system" << std::endl;
            return 1;
        }
        
        // Start the filtering system (blocking call)
        tiger_fox.Start();
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "❌ Unknown exception occurred" << std::endl;
        return 1;
    }
    
    return 0;
}