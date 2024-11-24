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

  int start(std::string_view iface1, std::string_view iface2);

  void stop();

  ~Filter() {
    stop();
  }

private:
  RuleSet m_rules;

  int m_pid1 = 0;
  int m_pid2 = 0;
};

} // namespace firewall

#endif /* Filter.hpp */
