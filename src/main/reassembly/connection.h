#ifndef SNIFFMYSHIT_SRC_MAIN_CONNECTION_H_
#define SNIFFMYSHIT_SRC_MAIN_CONNECTION_H_

#include <cstdint>
#include <unordered_map>
#include "../hash.h"

namespace sniff_my_shit {
struct Connection {
  uint16_t src_port;
  pcpp::IPAddress src_addr;
  uint16_t dst_port;
  pcpp::IPAddress dst_addr;
  bool operator==(const Connection &rhs) const {
    return src_port == rhs.src_port &&
        src_addr == rhs.src_addr &&
        dst_port == rhs.dst_port &&
        dst_addr == rhs.dst_addr;
  }
  bool operator!=(const Connection &rhs) const {
    return !(rhs == *this);
  }
  Connection() : src_port(0), src_addr(), dst_port(0), dst_addr() {}
  Connection(const uint32_t a_src_port,
             const pcpp::IPAddress &a_src_addr,
             const uint32_t a_dst_port,
             const pcpp::IPAddress &a_dst_addr)
      : src_port(a_src_port), src_addr(a_src_addr), dst_port(a_dst_port), dst_addr(a_dst_addr) {}
};

struct FragmentKey {
  uint32_t stream_id;
  int8_t side;
  bool operator==(const FragmentKey &rhs) const {
    return stream_id == rhs.stream_id &&
        side == rhs.side;
  }
  bool operator!=(const FragmentKey &rhs) const {
    return !(rhs == *this);
  }
};

struct ConnectionInfo {
  uint32_t request_stream_id;
  uint32_t response_stream_id;
  std::unique_ptr<std::unordered_map<FragmentKey, std::vector<uint8_t>>> fragment_map;
};

using ConnectionFragmentsMap = std::unordered_map<Connection, ConnectionInfo>;
using FragmentsMap = std::unordered_map<FragmentKey, std::vector<uint8_t>>;
}

template<>
struct std::hash<pcpp::IPAddress> {
  std::size_t operator()(const pcpp::IPAddress &s) const noexcept {
    if (s.isIPv4()) {
      return s.getIPv4().toInt();
    } else {
      auto data = s.getIPv6().toBytes();
      std::size_t result = 0;
      for (std::size_t i = 0; i < 16; ++i) {
        result ^= std::hash<uint8_t>{}(data[i]) + 0x9e3779b9 + (result << 6) + (result >> 2);
      }
      return result;
    }
  }
};

template<>
struct std::hash<sniff_my_shit::Connection> {
  std::size_t operator()(const sniff_my_shit::Connection &s) const noexcept {
    std::size_t res = 0;
    sniff_my_shit::hash_combine(res, s.src_port);
    sniff_my_shit::hash_combine(res, s.src_addr.toString());
    sniff_my_shit::hash_combine(res, s.dst_port);
    sniff_my_shit::hash_combine(res, s.dst_addr.toString());
    return res;
  }
};

template<>
struct std::hash<sniff_my_shit::FragmentKey> {
  std::size_t operator()(const sniff_my_shit::FragmentKey &s) const noexcept {
    std::size_t res = 0;
    sniff_my_shit::hash_combine(res, s.stream_id);
    sniff_my_shit::hash_combine(res, s.side);
    return res;
  }
};
#endif //SNIFFMYSHIT_SRC_MAIN_CONNECTION_H_
