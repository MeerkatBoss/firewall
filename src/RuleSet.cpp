#include "RuleSet.hpp"
#include "Exceptions.hpp"
#include "Rule.hpp"
#include <stdexcept>
#include <string_view>
#include <utility>

namespace firewall {

bool RuleSet::acceptPacket(const Packet& packet) {
  for (const auto& rule : m_rules) {
    auto result = rule.matchPacket(packet);
    if (result == Rule::Result::Match) {
      return m_type == Type::Whitelist;
    }
  }

  return m_type == Type::Blacklist;
}

static std::string_view trim(std::string_view str);
static std::pair<std::string_view, std::string_view> split(std::string_view str);

template <RuleSet::Type T>
void RuleSet::Builder<T>::readFromStream(std::istream& in) && {
  m_set.m_rules.clear();
  m_set.m_type = T;

  std::string line;
  size_t line_num = 0;
  while (std::getline(in, line)) {
    ++line_num;
    std::string_view trimmed = trim(line);
    auto [field, value] = split(trimmed);
    try {
      if (field == "src.ip") {
        m_set.m_rules.emplace_back(Rule::matchSourceIp(value));
      } else if (field == "src.port") {
        m_set.m_rules.emplace_back(Rule::matchSourcePort(value));
      } else if (field == "dst.ip") {
        m_set.m_rules.emplace_back(Rule::matchDestinationIp(value));
      } else if (field == "dst.port") {
        m_set.m_rules.emplace_back(Rule::matchDestinationPort(value));
      } else if (field == "proto") {
        m_set.m_rules.emplace_back(Rule::matchProtocol(value));
      } else {
        throw InvalidConfig(line_num, line);
      }
    } catch (const std::invalid_argument& e) {
      throw InvalidConfig(line_num, line);
    }
  }
}

template void
RuleSet::Builder<RuleSet::Type::Whitelist>::readFromStream(std::istream& in) &&;

template void
RuleSet::Builder<RuleSet::Type::Blacklist>::readFromStream(std::istream& in) &&;

static std::string_view trim(std::string_view str) {
  size_t prefix = str.find_first_not_of(" \t\r\v");
  size_t suffix = str.find_last_not_of(" \t\r\v");
  if (suffix == std::string_view::npos || prefix == std::string_view::npos) {
    return "";
  }

  str.remove_suffix(str.length() - suffix - 1);
  str.remove_prefix(prefix);

  return str;
}

static std::pair<std::string_view, std::string_view> split(std::string_view str) {
  size_t prefix = str.find_first_of(" \t\r\v");
  if (prefix == std::string_view::npos) {
    return std::make_pair(str, std::string_view(""));
  }
  std::string_view first = str.substr(0, prefix);
  str.remove_prefix(prefix);

  size_t skip = str.find_first_not_of(" \t\r\v");
  str.remove_prefix(skip);
  return std::make_pair(first, str);
}

} // namespace firewall
