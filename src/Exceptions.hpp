/**
 * @file Exceptions.hpp
 * @author MeerkatBoss (solodovnikov.ia@phystech.su)
 *
 * @brief
 *
 * @version 0.0.1
 * @date 2024-11-24
 *
 * @copyright Copyright MeerkatBoss (c) 2024
 */
#ifndef __EXCEPTIONS_HPP
#define __EXCEPTIONS_HPP

#include <stdexcept>
#include <string>

namespace firewall {

class InvalidConfig final : public std::runtime_error {
public:
  InvalidConfig(size_t line_num, std::string_view line) :
    std::runtime_error(
        std::to_string(line_num).append(": ").append(line)
    ),
    m_line_num(line_num),
    m_line(line) {
  }

  size_t getLineNumber() const {
    return m_line_num;
  }

  std::string_view getLine() const {
    return m_line;
  }

private:
  size_t m_line_num;
  std::string m_line;
};

} // namespace firewall

#endif /* Exceptions.hpp */
