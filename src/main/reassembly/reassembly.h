#ifndef SNIFFMYSHIT_SRC_MAIN_REASSEMBLE_REASSEMBLE_H_
#define SNIFFMYSHIT_SRC_MAIN_REASSEMBLE_REASSEMBLE_H_

#include <memory>
#include <unordered_map>
#include "IPReassembly.h"
#include "TcpReassembly.h"
#include "connection.h"
#include "../handler.h"
#include "parser/http1Parser.h"

#define IP_REASSEMBLY_TYPE 0x0
#define TCP_REASSEMBLY_TYPE 0x1
#define HTTP_REASSEMBLY_TYPE 0x2

namespace sniff_my_shit {

class IpReassembly : public Handler {
 private:
  pcpp::IPReassembly ip_reassembly_;
 public:
  explicit IpReassembly(std::unique_ptr<Handler> a_next_reassemble_)
      : Handler(std::move(a_next_reassemble_)){}
  void handle(std::unique_ptr<Data> data) override;
};

void tcpMessageReady(int8_t side, const pcpp::TcpStreamData &tcpData, void *userCookie);
void connectionClosed(const pcpp::ConnectionData &connectionData,
                      [[maybe_unused]] pcpp::TcpReassembly::ConnectionEndReason reason,
                      void *userCookie);

class TcpReassembly : public Handler {
 private:
  pcpp::TcpReassembly tcp_reassembly_;
 public:
  explicit TcpReassembly(std::unique_ptr<Handler> next_reassemble_) : Handler(std::move(next_reassemble_)),
                                                                      tcp_reassembly_(tcpMessageReady,
                                                                                      this,
                                                                                      nullptr,
                                                                                      connectionClosed) {}
  void handle(std::unique_ptr<Data> data) override;
};

struct HttpReassemblyData {
  const pcpp::TcpStreamData *tcp_stream_data;
  int8_t side;
};

class HttpReassembly : public Handler {
 public:
  explicit HttpReassembly(std::unique_ptr<Handler> next_handler) : Handler(std::move(next_handler)), http_parser_() {};
  void handle(std::unique_ptr<Data> data) override;
  void connection_closed(const pcpp::ConnectionData &connectionData) override;
 private:
  ConnectionFragmentsMap fragment_map_;
  Http1Parser http_parser_;
};
}
#endif //SNIFFMYSHIT_SRC_MAIN_REASSEMBLE_REASSEMBLE_H_
