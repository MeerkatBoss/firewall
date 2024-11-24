/**
 * @file Filter.hpp
 * @author MeerkatBoss (solodovnikov.ia@phystech.su)
 *
 * @brief
 *
 * @version 0.0.1
 * @date 2024-11-24
 *
 * @copyright Copyright MeerkatBoss (c) 2024
 */
#ifndef __FILTER_HPP
#define __FILTER_HPP

#include "RuleSet.hpp"

#include <string_view>

namespace firewall {

class Filter {
public:
  Filter(RuleSet&& rules) : m_rules(std::move(rules)) {
  }

  void filterPackets(std::string_view from, std::string_view to);

private:
  RuleSet m_rules;
};

} // namespace firewall

#endif /* Filter.hpp */
