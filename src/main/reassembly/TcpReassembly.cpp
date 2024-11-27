#include "reassembly.h"

namespace SniffMyShit {

using std::unique_ptr, std::make_unique, std::runtime_error, std::to_string, pcpp::Packet, pcpp::TcpStreamData;
void TcpReassembly::handle(std::unique_ptr<Data> data) {
  if (data->type != TCP_REASSEMBLY_TYPE) {
    throw runtime_error("Unexpected data type in TCP handle: " + to_string(data->type));
  }
  auto packet = static_cast<Packet *>(data->payload);
  tcp_reassembly_.reassemblePacket(*packet);
}

void tcpMessageReady(int8_t side, const TcpStreamData &tcpData, void *userCookie) {
  auto tcpReassembly = static_cast<TcpReassembly *>(userCookie);
  HttpReassemblyData http_reassembly_data{
      &tcpData,
      side,
  };
  tcpReassembly->pass_next(make_unique<Data>(
      Data{HTTP_REASSEMBLY_TYPE, &http_reassembly_data})
  );
}

void connectionClosed(const pcpp::ConnectionData &connectionData,
                      pcpp::TcpReassembly::ConnectionEndReason reason,
                      void *userCookie) {
  auto tcpReassembly = static_cast<TcpReassembly *>(userCookie);
  tcpReassembly->connection_closed(connectionData);
}
}
