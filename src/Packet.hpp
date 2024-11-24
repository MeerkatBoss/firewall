/**
 * @file Packet.hpp
 * @author MeerkatBoss (solodovnikov.ia@phystech.su)
 *
 * @brief
 *
 * @version 0.0.1
 * @date 2024-11-24
 *
 * @copyright Copyright MeerkatBoss (c) 2024
 */
#ifndef __PACKET_HPP
#define __PACKET_HPP

#include <arpa/inet.h>

namespace firewall {

enum class Protocol {
  ICMP,
  TCP,
  UDP
};

struct Packet {
  in_addr src_addr;
  in_addr dst_addr;
  Protocol protocol;
  uint16_t src_port;
  uint16_t dst_port;
};

} // namespace firewall

#endif /* Packet.hpp */
