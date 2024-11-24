/**
 * @file RuleSet.hpp
 * @author MeerkatBoss (solodovnikov.ia@phystech.su)
 *
 * @brief
 *
 * @version 0.0.1
 * @date 2024-11-24
 *
 * @copyright Copyright MeerkatBoss (c) 2024
 */
#ifndef __RULE_SET_HPP
#define __RULE_SET_HPP

#include <istream>
#include <vector>

#include "Packet.hpp"
#include "Rule.hpp"

namespace firewall {

class RuleSet {
public:
  enum class Type {
    Whitelist,
    Blacklist
  };

private:
  template <Type T>
  class Builder {
  public:
    Builder(RuleSet& rules) : m_rules(rules) {}
    friend std::istream& operator>>(std::istream& in, Builder&& builder) {
      builder.readFromStream(in);
      return in;
    }

  private:
    void readFromStream(std::istream& in) &&;

    RuleSet& m_rules;
  };

public:
  RuleSet() = default;

  static Builder<Type::Whitelist> whitelist(RuleSet& set);
  static Builder<Type::Blacklist> blacklist(RuleSet& set);

  bool acceptPacket(const Packet& packet);

private:
  Type m_type = Type::Blacklist;
  std::vector<Rule> m_rules;
};

} // namespace firewall

#endif /* RuleSet.hpp */
