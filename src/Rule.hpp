/**
 * @file Rule.hpp
 * @author MeerkatBoss (solodovnikov.ia@phystech.su)
 *
 * @brief
 *
 * @version 0.0.1
 * @date 2024-11-24
 *
 * @copyright Copyright MeerkatBoss (c) 2024
 */
#ifndef __RULE_HPP
#define __RULE_HPP

#include <arpa/inet.h>
#include <cstdint>
#include <string_view>

#include "Packet.hpp"

namespace firewall {

class Rule {
public:
  enum class Type {
    SourceIp,
    DestinationIp,
    Protocol,
    SourcePort,
    DestinationPort
  };

  enum class Result {
    Match,
    NoMatch,
    Skip
  };

  Rule() = delete;

  static Rule matchSourceIp(std::string_view ip);
  static Rule matchDestinationIp(std::string_view ip);
  static Rule matchProtocol(std::string_view protocol);
  static Rule matchSourcePort(std::string_view port);
  static Rule matchDestinationPort(std::string_view port);

  Result matchPacket(const Packet& packet) const;

private:

  Type m_type;
  union {
    in_addr m_ip;
    Protocol m_protocol;
    uint16_t m_port;
  };

};

} // namespace firewall

#endif /* Rule.hpp */
