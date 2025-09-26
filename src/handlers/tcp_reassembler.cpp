#include "tcp_reassembler.h"
#include "../utils.h"

#include <iostream>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <thread>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// TCPStream implementation
TCPStream::TCPStream(const std::string& src_ip, uint16_t src_port, 
                     const std::string& dst_ip, uint16_t dst_port)
    : src_ip_(src_ip), src_port_(src_port), dst_ip_(dst_ip), dst_port_(dst_port),
      next_expected_seq_(0), http_detected_(false), in_headers_(true),
      content_length_(0), body_received_(0) {
    UpdateActivity();
}

std::unique_ptr<HTTPData> TCPStream::AddSegment(uint32_t seq_num, const std::string& data) {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    
    UpdateActivity();
    
    if (data.empty()) {
        return nullptr;
    }
    
    // Store segment
    TCPSegment segment;
    segment.seq_num = seq_num;
    segment.data = data;
    segment.timestamp = GetCurrentTimeMs();
    
    segments_[seq_num] = segment;
    
    // Try to assemble consecutive segments
    AssembleSegments();
    
    // Detect HTTP if not already detected
    if (!http_detected_) {
        DetectHTTP();
    }
    
    // Parse HTTP if we have HTTP data
    if (http_detected_ && !assembled_data_.empty()) {
        return ParseHTTP();
    }
    
    return nullptr;
}

void TCPStream::AssembleSegments() {
    if (next_expected_seq_ == 0 && !segments_.empty()) {
        next_expected_seq_ = segments_.begin()->first;
    }
    
    while (!segments_.empty()) {
        auto it = segments_.find(next_expected_seq_);
        if (it == segments_.end()) {
            break; // Gap in sequence
        }
        
        assembled_data_ += it->second.data;
        next_expected_seq_ += it->second.data.length();
        segments_.erase(it);
        
        // Limit assembled data to prevent memory exhaustion
        if (assembled_data_.length() > 1024 * 1024) { // 1MB limit
            assembled_data_ = assembled_data_.substr(assembled_data_.length() - 512 * 1024);
        }
    }
}

bool TCPStream::DetectHTTP() {
    if (assembled_data_.length() < 16) {
        return false;
    }
    
    std::string data_start = assembled_data_.substr(0, 200);
    
    // Check for HTTP request methods
    const std::vector<std::string> http_methods = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "
    };
    
    for (const auto& method : http_methods) {
        if (data_start.find(method) == 0) {
            http_detected_ = true;
            return true;
        }
    }
    
    // Check for HTTP response
    if (data_start.find("HTTP/") == 0) {
        http_detected_ = true;
        return true;
    }
    
    return false;
}

std::unique_ptr<HTTPData> TCPStream::ParseHTTP() {
    if (assembled_data_.empty()) {
        return nullptr;
    }
    
    // Find end of headers
    size_t headers_end = assembled_data_.find("\r\n\r\n");
    if (headers_end == std::string::npos) {
        // Headers not complete yet
        return nullptr;
    }
    
    std::string headers_part = assembled_data_.substr(0, headers_end);
    std::string body_part = assembled_data_.substr(headers_end + 4);
    
    // Parse HTTP request
    return ParseHTTPRequest(headers_part + "\r\n\r\n" + body_part);
}

std::unique_ptr<HTTPData> TCPStream::ParseHTTPRequest(const std::string& data) {
    auto http_data = std::make_unique<HTTPData>();
    
    std::istringstream stream(data);
    std::string line;
    
    // Parse request line
    if (!std::getline(stream, line)) {
        return nullptr;
    }
    
    // Remove \r if present
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    
    std::istringstream request_line(line);
    std::string method, uri, version;
    
    if (!(request_line >> method >> uri >> version)) {
        return nullptr;
    }
    
    http_data->method = method;
    http_data->uri = uri;
    http_data->version = version;
    
    // Parse headers
    int content_length = 0;
    while (std::getline(stream, line)) {
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        if (line.empty()) {
            break; // End of headers
        }
        
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string header_name = line.substr(0, colon_pos);
            std::string header_value = line.substr(colon_pos + 1);
            
            // Trim whitespace
            header_name = StringUtils::Trim(header_name);
            header_value = StringUtils::Trim(header_value);
            
            // Convert header name to lowercase
            std::transform(header_name.begin(), header_name.end(), header_name.begin(), ::tolower);
            
            http_data->headers[header_name] = header_value;
            
            // Extract important headers
            if (header_name == "host") {
                http_data->host = header_value;
            } else if (header_name == "user-agent") {
                http_data->user_agent = header_value;
            } else if (header_name == "content-length") {
                try {
                    content_length = std::stoi(header_value);
                } catch (...) {
                    content_length = 0;
                }
            }
        }
    }
    
    // Read body
    std::string body;
    std::string body_line;
    while (std::getline(stream, body_line)) {
        body += body_line + "\n";
    }
    
    http_data->payload = body;
    
    // Check if request is complete
    if (content_length > 0 && (int)body.length() < content_length) {
        // Request not complete yet
        return nullptr;
    }
    
    http_data->complete = true;
    return http_data;
}

bool TCPStream::IsExpired(uint64_t timeout_ms) const {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    return (GetCurrentTimeMs() - last_activity_) > timeout_ms;
}

std::string TCPStream::GetKey() const {
    return src_ip_ + ":" + std::to_string(src_port_) + "->" + 
           dst_ip_ + ":" + std::to_string(dst_port_);
}

std::string TCPStream::GetInfo() const {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    return GetKey() + " (segments: " + std::to_string(segments_.size()) + 
           ", assembled: " + std::to_string(assembled_data_.length()) + " bytes)";
}

uint64_t TCPStream::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
}

void TCPStream::UpdateActivity() {
    last_activity_ = GetCurrentTimeMs();
}

// TCPReassembler implementation
TCPReassembler::TCPReassembler(size_t max_streams, uint64_t timeout_ms)
    : max_streams_(max_streams), stream_timeout_ms_(timeout_ms), cleanup_running_(true),
      total_streams_(0), active_streams_(0), http_streams_(0), 
      reassembled_requests_(0), expired_streams_(0) {
    
    // Start cleanup thread
    cleanup_thread_ = std::thread(&TCPReassembler::CleanupLoop, this);
    
    std::cout << "🔧 TCP Reassembler initialized:" << std::endl;
    std::cout << "   Max streams: " << max_streams_ << std::endl;
    std::cout << "   Timeout: " << stream_timeout_ms_ << "ms" << std::endl;
}

TCPReassembler::~TCPReassembler() {
    Cleanup();
}

std::unique_ptr<HTTPData> TCPReassembler::ProcessPacket(unsigned char* data, int len, 
                                                       const PacketData& packet) {
    // Extract TCP payload
    std::string tcp_payload = ExtractTCPPayload(data, len, packet);
    if (tcp_payload.empty()) {
        return nullptr;
    }
    
    // Get or create stream
    std::string stream_key = GetStreamKey(packet);
    TCPStream* stream = GetOrCreateStream(stream_key, packet);
    
    if (!stream) {
        return nullptr;
    }
    
    // Add segment to stream
    auto http_data = stream->AddSegment(packet.seq_num, tcp_payload);
    
    if (http_data) {
        reassembled_requests_.fetch_add(1, std::memory_order_relaxed);
    }
    
    return http_data;
}

std::string TCPReassembler::GetStreamKey(const PacketData& packet) const {
    // Normalize stream direction (smaller IP:port first for bidirectional tracking)
    std::string key1 = packet.src_ip + ":" + std::to_string(packet.src_port) + "->" +
                      packet.dst_ip + ":" + std::to_string(packet.dst_port);
    std::string key2 = packet.dst_ip + ":" + std::to_string(packet.dst_port) + "->" +
                      packet.src_ip + ":" + std::to_string(packet.src_port);
    
    return (key1 < key2) ? key1 : key2;
}

TCPStream* TCPReassembler::GetOrCreateStream(const std::string& key, const PacketData& packet) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    
    auto it = streams_.find(key);
    if (it != streams_.end()) {
        return it->second.get();
    }
    
    // Check if we need to make room for new stream
    if (streams_.size() >= max_streams_) {
        CleanupExpiredStreams();
        
        if (streams_.size() >= max_streams_) {
            // Still full, can't create new stream
            return nullptr;
        }
    }
    
    // Create new stream
    auto stream = std::make_unique<TCPStream>(packet.src_ip, packet.src_port,
                                             packet.dst_ip, packet.dst_port);
    TCPStream* stream_ptr = stream.get();
    
    streams_[key] = std::move(stream);
    
    total_streams_.fetch_add(1, std::memory_order_relaxed);
    active_streams_.store(streams_.size(), std::memory_order_relaxed);
    
    return stream_ptr;
}

std::string TCPReassembler::ExtractTCPPayload(unsigned char* data, int len, 
                                             const PacketData& packet) const {
    if (len < sizeof(struct iphdr) + sizeof(struct tcphdr)) {
        return "";
    }
    
    struct iphdr* ip_header = (struct iphdr*)data;
    int ip_header_len = ip_header->ihl * 4;
    
    if (len <= ip_header_len) {
        return "";
    }
    
    struct tcphdr* tcp_header = (struct tcphdr*)(data + ip_header_len);
    int tcp_header_len = tcp_header->doff * 4;
    
    int payload_offset = ip_header_len + tcp_header_len;
    if (len <= payload_offset) {
        return "";
    }
    
    int payload_len = len - payload_offset;
    return std::string((char*)(data + payload_offset), payload_len);
}

void TCPReassembler::CleanupExpiredStreams() {
    // This function assumes streams_mutex_ is already locked
    
    std::vector<std::string> expired_keys;
    
    for (const auto& [key, stream] : streams_) {
        if (stream->IsExpired(stream_timeout_ms_)) {
            expired_keys.push_back(key);
        }
    }
    
    for (const auto& key : expired_keys) {
        streams_.erase(key);
        expired_streams_.fetch_add(1, std::memory_order_relaxed);
    }
    
    active_streams_.store(streams_.size(), std::memory_order_relaxed);
    
    if (!expired_keys.empty()) {
        LOG_DEBUG(true, "Cleaned up " + std::to_string(expired_keys.size()) + " expired TCP streams");
    }
}

void TCPReassembler::CleanupLoop() {
    while (cleanup_running_.load()) {
        try {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            
            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                CleanupExpiredStreams();
            }
        } catch (const std::exception& e) {
            std::cerr << "❌ Error in TCP cleanup loop: " << e.what() << std::endl;
        }
    }
}

TCPReassembler::Stats TCPReassembler::GetStats() const {
    Stats stats;
    stats.total_streams = total_streams_.load();
    stats.active_streams = active_streams_.load();
    stats.http_streams = http_streams_.load();
    stats.reassembled_requests = reassembled_requests_.load();
    stats.expired_streams = expired_streams_.load();
    return stats;
}

void TCPReassembler::PrintStats() const {
    auto stats = GetStats();
    
    std::cout << "\n🔄 TCP Reassembler Statistics:" << std::endl;
    std::cout << "   Total streams: " << stats.total_streams << std::endl;
    std::cout << "   Active streams: " << stats.active_streams << std::endl;
    std::cout << "   HTTP streams: " << stats.http_streams << std::endl;
    std::cout << "   Reassembled requests: " << stats.reassembled_requests << std::endl;
    std::cout << "   Expired streams: " << stats.expired_streams << std::endl;
}

void TCPReassembler::Cleanup() {
    cleanup_running_.store(false);
    
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
    
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_.clear();
    }
    
    std::cout << "🧹 TCP Reassembler cleaned up" << std::endl;
}