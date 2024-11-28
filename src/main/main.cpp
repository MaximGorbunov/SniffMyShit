#include <iostream>
#include <string>
#include "PcapLiveDeviceList.h"
#include "IPLayer.h"
#include "options.h"
#include "IPReassembly.h"
#include "reassembly/reassembly.h"
#include "filter/httpFilter.h"
#include "collections/concurrentQueue.h"

using pcpp::RawPacket, pcpp::PcapLiveDevice,
    pcpp::PcapLiveDeviceList, std::string, sniff_my_shit::ConcurrentQueue,
    sniff_my_shit::TcpReassembly, sniff_my_shit::HttpReassembly, sniff_my_shit::Data, sniff_my_shit::parseOptions;

namespace {
ConcurrentQueue<RawPacket> packet_queue{};

void processPacket(const RawPacket *packet,
                   [[maybe_unused]] PcapLiveDevice *dev,
                   [[maybe_unused]] void *cookie) {
  packet_queue.push(*packet);
}

PcapLiveDevice *chooseLiveDevice(const string &chosenInterface) {
  const PcapLiveDeviceList &list = PcapLiveDeviceList::getInstance();
  PcapLiveDevice *device;
  if (!chosenInterface.empty()) {
    device = list.getPcapLiveDeviceByName(chosenInterface);
    if (device != nullptr) {
      return device;
    }
    std::cout << "Wrong device name! Write interface name again:" << std::endl;
  }
  for (const auto &item : list.getPcapLiveDevicesList()) {
    std::cout << "Interface name: " << item->getName() << " IPv4: " << item->getIPv4Address() << std::endl;
  }
  std::cout << "Choose interface from list:" << std::endl;
  std::string interface;
  std::getline(std::cin, interface);
  device = list.getPcapLiveDeviceByName(interface);
  while (device == nullptr) {
    std::cout << "Wrong device name! Write interface name again:" << std::endl;
    std::getline(std::cin, interface);
    device = list.getPcapLiveDeviceByName(interface);
  }
  return device;
}
}

int main(int argc, char *argv[]) {
  auto options = parseOptions(argc, argv);
  PcapLiveDevice *device = chooseLiveDevice(options->interface);
  if (!device->open(PcapLiveDevice::DeviceConfiguration{pcpp::PcapLiveDevice::Promiscuous, 0, 10 * 1024 * 1024,
                                                        pcpp::PcapLiveDevice::PCPP_INOUT, 10 * 1024 * 1024})) {
    std::cout << "Failed to open device!" << std::endl;
    return 1;
  }
  std::cout << "Starting packet capture..." << std::endl;
  auto filter = pcpp::PortFilter{options->port, pcpp::Direction::SRC_OR_DST};
  device->setFilter(filter);

  auto http_filter = std::make_unique<sniff_my_shit::HttpFilter>(
      &options->request_url_filters,
      &options->request_headers_filters,
      &options->request_body_filters,
      &options->response_status_filters,
      &options->response_headers_filters,
      &options->response_body_filters
  );
  auto l7 = std::make_unique<sniff_my_shit::HttpReassembly>(std::move(http_filter));
  auto l4 = std::make_unique<sniff_my_shit::TcpReassembly>(std::move(l7));
  auto l3 = sniff_my_shit::IpReassembly(std::move(l4));
  device->startCapture(processPacket, nullptr);
  auto start = std::chrono::system_clock::now();
  while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - start).count()
      < options->time) {
    RawPacket raw_packet;
    if (packet_queue.try_pop(raw_packet)) {
      l3.handle(std::make_unique<Data>(
          Data{.type=IP_REASSEMBLY_TYPE, .payload=static_cast<void *>(&raw_packet)}
      ));
    }
  }
  std::cout << "Stopping packet capture..." << std::endl;
  device->stopCapture();
  device->close();
  return 0;
}