#include <Packet.h>
#include <IPReassembly.h>
#include "reassembly.h"

namespace sniff_my_shit {
void IpReassembly::handle(std::unique_ptr<Data> data) {
  if (data->type != IP_REASSEMBLY_TYPE) {
    throw std::runtime_error("Unexpected data type in IP handle: " + std::to_string(data->type));
  }
  auto *packet = static_cast<pcpp::RawPacket *>(data->payload);
  pcpp::Packet parsed_packet(packet);
  pcpp::IPReassembly::ReassemblyStatus ip_reassembly_status;
  auto *processed_packet_ptr = ip_reassembly_.processPacket(&parsed_packet, ip_reassembly_status);
  if (ip_reassembly_status == pcpp::IPReassembly::REASSEMBLED) {
    auto reassembled_ip_packet = std::unique_ptr<pcpp::Packet>(processed_packet_ptr);
    if (reassembled_ip_packet != nullptr && reassembled_ip_packet->isPacketOfType(pcpp::IP)) {
      data->type = TCP_REASSEMBLY_TYPE;
      data->payload = reassembled_ip_packet.get();
      pass_next(std::move(data));
    }
  } else if (ip_reassembly_status == pcpp::IPReassembly::NON_FRAGMENT) {
    data->type = TCP_REASSEMBLY_TYPE;
    data->payload = &parsed_packet;
    pass_next(std::move(data));
  }
}
}