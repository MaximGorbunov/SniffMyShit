#include <Packet.h>
#include <IPReassembly.h>
#include "reassembly.h"

namespace SniffMyShit {
void IpReassembly::handle(std::unique_ptr<Data> data) {
  if (data->type != IP_REASSEMBLY_TYPE) {
    throw std::runtime_error("Unexpected data type in IP handle: " + std::to_string(data->type));
  }
  auto packet = static_cast<pcpp::RawPacket *>(data->payload);
  pcpp::Packet parsedPacket(packet);
  pcpp::IPReassembly::ReassemblyStatus ipReassemblyStatus;
  auto processedPacketPtr = ip_reassembly_.processPacket(&parsedPacket, ipReassemblyStatus);
  if (ipReassemblyStatus == pcpp::IPReassembly::REASSEMBLED) {
    auto reassembledIpPacket = std::unique_ptr<pcpp::Packet>(processedPacketPtr);
    if (reassembledIpPacket != nullptr && reassembledIpPacket->isPacketOfType(pcpp::IP)) {
      data->type = TCP_REASSEMBLY_TYPE;
      data->payload = reassembledIpPacket.get();
      pass_next(std::move(data));
    }
  } else if (ipReassemblyStatus == pcpp::IPReassembly::NON_FRAGMENT) {
    data->type = TCP_REASSEMBLY_TYPE;
    data->payload = &parsedPacket;
    pass_next(std::move(data));
  }
}
}