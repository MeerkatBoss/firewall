#include "Rule.hpp"
#include "Packet.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <string_view>

namespace firewall {

static in_addr ipFromString(std::string_view ip);
static uint16_t portFromString(std::string_view ip);

Rule Rule::matchSourceIp(std::string_view ip) {
  return Rule(Type::SourceIp, ipFromString(ip));
}

Rule Rule::matchDestinationIp(std::string_view ip) {
  return Rule(Type::DestinationIp, ipFromString(ip));
}

Rule Rule::matchSourcePort(std::string_view port) {
  return Rule(Type::SourcePort, portFromString(port));
}

Rule Rule::matchDestinationPort(std::string_view port) {
  return Rule(Type::DestinationPort, portFromString(port));
}

Rule Rule::matchProtocol(std::string_view protocol) {
  if (protocol == "icmp") {
    return Rule(Type::Protocol, Protocol::ICMP);
  }
  if (protocol == "tcp") {
    return Rule(Type::Protocol, Protocol::TCP);
  }
  if (protocol == "udp") {
    return Rule(Type::Protocol, Protocol::UDP);
  }
  throw std::invalid_argument(std::string(protocol));
}

static bool operator==(const in_addr& lhs, const in_addr& rhs) {
  return memcmp(&lhs, &rhs, sizeof(lhs)) == 0;
}

static bool hasPort(const Packet& packet) {
  return packet.protocol == Protocol::TCP || packet.protocol == Protocol::UDP;
}

Rule::Result Rule::matchPacket(const Packet& packet) const {
  switch (m_type) {
  case Type::SourceIp:
    return packet.src_addr == m_ip ? Result::Match : Result::NoMatch;
  case Type::DestinationIp:
    return packet.dst_addr == m_ip ? Result::Match : Result::NoMatch;
  case Type::Protocol:
    return packet.protocol == m_protocol ? Result::Match : Result::NoMatch;
  case Type::SourcePort:
    if (!hasPort(packet))
      return Result::Skip;
    return packet.src_port == m_port ? Result::Match : Result::NoMatch;
  case Type::DestinationPort:
    if (!hasPort(packet))
      return Result::Skip;
    return packet.dst_port == m_port ? Result::Match : Result::NoMatch;
  default:
    assert(0 && "Unreachable");
    break;
  }
}

static in_addr ipFromString(std::string_view ip) {
  static constexpr size_t MaxAddrLen = 3*4 + 3;
  static constexpr size_t MinAddrLen = 4 + 3;

  if (ip.length() < MinAddrLen) {
    throw std::invalid_argument(std::string(ip));
  }
  if (ip.length() > MaxAddrLen) {
    throw std::invalid_argument(std::string(ip));
  }

  // NUL-terminated string_view
  char buffer[MaxAddrLen + 1];
  std::fill(std::begin(buffer), std::end(buffer), 0);
  std::copy(ip.begin(), ip.end(), buffer);
  
  in_addr result;
  int success = inet_pton(AF_INET, buffer, &result);
  assert(success >= 0);
  if (!success) {
    throw std::invalid_argument(std::string(ip));
  }

  return result;
}

static uint16_t portFromString(std::string_view port) {
  static constexpr size_t MinPortLen = 1;
  static constexpr size_t MaxPortLen = 5;

  if (port.length() < MinPortLen) {
    throw std::invalid_argument(std::string(port));
  }
  if (port.length() > MaxPortLen) {
    throw std::invalid_argument(std::string(port));
  }

  // NUL-terminated string_view
  char buffer[MaxPortLen + 1];
  std::fill(std::begin(buffer), std::end(buffer), 0);
  std::copy(port.begin(), port.end(), buffer);

  uint16_t result = 0;
  int read_count = 0;
  int status = sscanf(buffer, "%hu%n", &result, &read_count);
  if (status != 1 || read_count != (int) port.length()) {
    throw std::invalid_argument(std::string(port));
  }

  return result;
}

} // namespace firewall
