#include "Filter.hpp"

#include <cassert>
#include <csignal>
#include <stdexcept>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>

#include "Packet.hpp"
#include "RuleSet.hpp"
namespace firewall {

static int getIfaceSocket(std::string_view iface_name);
static void filterWith(int from, int to, const RuleSet& rules);
static size_t checkPacket(int from, const RuleSet& rules);
static void forwardPacket(int from, int to, size_t size);

int Filter::start(std::string_view iface1, std::string_view iface2) {
  int fd1 = getIfaceSocket(iface1);
  if (fd1 < 0) {
    return -1;
  }
  int fd2 = getIfaceSocket(iface2);
  if (fd2 < 0) {
    close(fd1);
    return -1;
  }

  m_pid1 = fork();
  if (m_pid1 == 0) {
    filterWith(fd1, fd2, m_rules);
    assert(0 && "Unreachable");
  }
  assert(m_pid1 > 0);
  
  m_pid2 = fork();
  if (m_pid2 == 0) {
    filterWith(fd2, fd1, m_rules);
    assert(0 && "Unreachable");
  }
  assert(m_pid2 > 0);

  close(fd1);
  close(fd2);
}

void Filter::stop() {
  int status = 0;
  if (m_pid1 != 0) {
    kill(m_pid1, SIGKILL);
    waitpid(m_pid1, &status, 0);
  }
  if (m_pid2 != 0) {
    kill(m_pid2, SIGKILL);
    waitpid(m_pid2, &status, 0);
  }
}

static int getIfaceSocket(std::string_view iface_name) {
  struct if_nameindex* head = if_nameindex();
  assert(head != NULL);
  long index = -1;
  for (const auto* cur = head; cur->if_name != NULL; ++cur) {
    if (iface_name == cur->if_name) {
      index = cur->if_index;
    }
  }
  if_freenameindex(head);

  if (index < 0) {
    return -1;
  }

  int sock = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
  if (sock < 0) {
    return sock;
  }
  struct sockaddr_ll addr = {};
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_ALL);
  addr.sll_ifindex = index;
  
  int res = bind(sock, (struct sockaddr*) &addr, sizeof(addr));
  if (res < 0) {
    return res;
  }

  return sock;
}

static void filterWith(int from, int to, const RuleSet& rules) {
  for (;;) {
    size_t size = checkPacket(from, rules);
    // If packet is accepted
    if (size > 0) {
      forwardPacket(from, to, size);
    }
  }
}

static size_t checkPacket(int from, const RuleSet& rules) {
  static constexpr size_t BufferSize =
    sizeof(ether_header) + sizeof(iphdr)
    + std::max(sizeof(udphdr), sizeof(tcphdr));

  char buffer[BufferSize];
  const char* buffer_front = buffer;
  int res = recv(from, buffer, BufferSize, MSG_PEEK | MSG_TRUNC);

  // We can't receive less than ether packet
  assert(res >= (int) sizeof(ether_header));
  const size_t packet_size = res;
  const ether_header* eth = (const ether_header*) buffer_front;
  buffer_front += sizeof(*eth);

  const int type = ntohs(eth->ether_type);
  if (type != ETHERTYPE_IP) {
    return packet_size;
  }

  assert(res >= (int) (sizeof(ether_header) + sizeof(iphdr)));
  Packet packet;
  const iphdr* ip = (const iphdr*) buffer_front;
  buffer_front += sizeof(*ip);

  packet.src_addr.s_addr = ip->saddr;
  packet.dst_addr.s_addr = ip->daddr;
  
  int proto = ip->protocol;
  if (ip->protocol == IPPROTO_ICMP) {
    packet.protocol = Protocol::ICMP;
    packet.src_port = 0;
    packet.dst_port = 0;
    return rules.acceptPacket(packet) ? packet_size : 0;
  }

  if (ip->protocol == IPPROTO_TCP) {
    packet.protocol = Protocol::TCP;
    const tcphdr* tcp = (const tcphdr*) buffer_front;
    buffer_front += sizeof(*tcp);
    packet.src_port = tcp->source;
    packet.dst_port = tcp->dest;

    return rules.acceptPacket(packet) ? packet_size : 0;
  }

  if (ip->protocol == IPPROTO_UDP) {
    packet.protocol = Protocol::UDP;
    const udphdr* udp = (const udphdr*) buffer_front;
    buffer_front += sizeof(*udp);
    packet.src_port = udp->source;
    packet.dst_port = udp->dest;

    return rules.acceptPacket(packet) ? packet_size : 0;
  }

  return packet_size;
}

static void forwardPacket(int from, int to, size_t size) {
  static constexpr size_t BufferSize = 4096;
  static char buffer[BufferSize];

  size_t remaining = size;

  while (remaining > 0) {
    size_t batch = std::min(BufferSize, remaining);
    int res = read(from, buffer, batch);
    assert(res > 0);
    size_t byte_count = res;
    res = write(to, buffer, byte_count);
    assert(res == (int) byte_count);

    remaining -= byte_count;
  }
}

} // namespace firewall
