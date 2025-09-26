#ifndef RULE_LOADER_H
#define RULE_LOADER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <nlohmann/json.hpp>

// Forward declaration
enum class RuleLayer;
enum class RuleType;
enum class RuleAction;
struct Rule;

class RuleLoader {
public:
    static std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>> 
    LoadRules(const std::string& file_path);
    
    static bool ValidateRulesFile(const std::string& file_path);
    
    static void PrintRulesSummary(const std::unordered_map<RuleLayer, std::vector<std::unique_ptr<Rule>>>& rules);

private:
    static std::unique_ptr<Rule> ParseRule(const nlohmann::json& rule_json);
    
    static RuleLayer ParseRuleLayer(int layer);
    static RuleType ParseRuleType(const std::string& type_str);
    static RuleAction ParseRuleAction(const std::string& action_str);
    
    static bool ValidateRule(const std::unique_ptr<Rule>& rule);
    
    // Rule type mapping
    static const std::unordered_map<std::string, RuleType> rule_type_map_;
    static const std::unordered_map<std::string, RuleAction> rule_action_map_;
};

#endif // RULE_LOADER_H