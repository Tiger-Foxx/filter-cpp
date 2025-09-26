#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <atomic>

// High-resolution timing utilities
class HighResTimer {
private:
    std::chrono::high_resolution_clock::time_point start_time_;
    
public:
    HighResTimer() : start_time_(std::chrono::high_resolution_clock::now()) {}
    
    void Reset() {
        start_time_ = std::chrono::high_resolution_clock::now();
    }
    
    double ElapsedMilliseconds() const {
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(now - start_time_);
        return duration.count() / 1000000.0; // Convert to milliseconds
    }
    
    double ElapsedMicroseconds() const {
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(now - start_time_);
        return duration.count() / 1000.0; // Convert to microseconds
    }
};

// Thread-safe statistics collection
class ThreadSafeStats {
private:
    mutable std::mutex mutex_;
    std::atomic<uint64_t> count_{0};
    std::atomic<double> total_time_{0.0};
    std::atomic<double> min_time_{std::numeric_limits<double>::max()};
    std::atomic<double> max_time_{0.0};
    
public:
    void Update(double time_ms) {
        count_.fetch_add(1, std::memory_order_relaxed);
        total_time_.fetch_add(time_ms, std::memory_order_relaxed);
        
        // Update min/max with compare-exchange
        double current_min = min_time_.load();
        while (time_ms < current_min && 
               !min_time_.compare_exchange_weak(current_min, time_ms)) {
            // Keep trying
        }
        
        double current_max = max_time_.load();
        while (time_ms > current_max && 
               !max_time_.compare_exchange_weak(current_max, time_ms)) {
            // Keep trying
        }
    }
    
    uint64_t GetCount() const { return count_.load(); }
    double GetAverage() const { 
        auto c = count_.load();
        return c > 0 ? total_time_.load() / c : 0.0; 
    }
    double GetMin() const { return min_time_.load(); }
    double GetMax() const { return max_time_.load(); }
    double GetTotal() const { return total_time_.load(); }
};

// String utilities
namespace StringUtils {
    std::vector<std::string> Split(const std::string& str, char delimiter);
    std::string Trim(const std::string& str);
    std::string ToLower(const std::string& str);
    bool StartsWith(const std::string& str, const std::string& prefix);
    bool EndsWith(const std::string& str, const std::string& suffix);
    bool Contains(const std::string& str, const std::string& substr);
}

// Network utilities
namespace NetworkUtils {
    bool IsPrivateIP(const std::string& ip);
    bool IsValidIPv4(const std::string& ip);
    bool IsValidIPv6(const std::string& ip);
    uint32_t IPv4ToUint32(const std::string& ip);
    bool IsInSubnet(const std::string& ip, const std::string& subnet);
}

// System utilities
namespace SystemUtils {
    int GetCPUCoreCount();
    bool IsRootUser();
    pid_t GetCurrentPID();
    void SetThreadAffinity(std::thread& thread, int core_id);
    void SetHighPriority();
}

// Performance measurement macros
#define MEASURE_TIME(var, code_block) do { \
    HighResTimer timer; \
    code_block; \
    var = timer.ElapsedMilliseconds(); \
} while(0)

#define LOG_DEBUG(debug_mode, message) do { \
    if (debug_mode) { \
        std::cout << "[DEBUG] " << message << std::endl; \
    } \
} while(0)

#endif // UTILS_H