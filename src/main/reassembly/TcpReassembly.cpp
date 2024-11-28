#include "reassembly.h"

namespace sniff_my_shit {

using std::unique_ptr, std::make_unique, std::runtime_error, std::to_string, pcpp::Packet, pcpp::TcpStreamData;
void TcpReassembly::handle(std::unique_ptr<Data> data) {
  if (data->type != TCP_REASSEMBLY_TYPE) {
    throw runtime_error("Unexpected data type in TCP handle: " + to_string(data->type));
  }
  auto *packet = static_cast<Packet *>(data->payload);
  tcp_reassembly_.reassemblePacket(*packet);
}

void tcpMessageReady(int8_t side, const TcpStreamData &tcpData, void *userCookie) {
  const auto *tcp_reassembly = static_cast<TcpReassembly *>(userCookie);
  HttpReassemblyData http_reassembly_data{
      .tcp_stream_data=&tcpData,
      .side=side,
  };
  tcp_reassembly->pass_next(make_unique<Data>(
      Data{.type=HTTP_REASSEMBLY_TYPE, .payload=&http_reassembly_data})
  );
}

void connectionClosed(const pcpp::ConnectionData &connectionData,
                      [[maybe_unused]] pcpp::TcpReassembly::ConnectionEndReason reason,
                      void *userCookie) {
  auto *tcp_reassembly = static_cast<TcpReassembly *>(userCookie);
  tcp_reassembly->connection_closed(connectionData);
}
}
