#include "reassembly.h"
#include "../filter/httpFilter.h"
#include <string>
#include <memory>

#ifndef HTTP_REQUEST
#define HTTP_REQUEST   0
#endif

#ifndef HTTP_RESPONSE
#define HTTP_RESPONSE  1
#endif

namespace SniffMyShit {

// There might be two cases or even both of them:
// 1. Http fragmented in a way that packet here won't contain complete HTTP entity
// 2. Http fragmented in a way that packet will contain multiple http entities
void HttpReassembly::handle(std::unique_ptr<Data> data) {
  if (data->type != HTTP_REASSEMBLY_TYPE) {
    throw std::runtime_error("Unexpected data type in HTTP handle: " + std::to_string(data->type));
  }

  auto httpData = static_cast<HttpReassemblyData *>(data->payload);
  size_t tcpDataLength = httpData->tcp_stream_data->getDataLength();

  auto connection = httpData->tcp_stream_data->getConnectionData();
  SniffMyShit::Connection connectionData{
      connection.srcPort,
      connection.srcIP,
      connection.dstPort,
      connection.dstIP
  };

  bool fragmented = false;
  auto searchConnection = fragment_map_.find(connectionData);
  std::vector<uint8_t> *fragments = nullptr;
  FragmentKey fragment_key{0, httpData->side};
  if (searchConnection == fragment_map_.end()) {
    fragment_map_.insert({connectionData, ConnectionInfo{0, 0, std::unique_ptr<FragmentsMap>(nullptr)}});
    searchConnection = fragment_map_.find(connectionData);
  } else {
    if (httpData->side == HTTP_REQUEST) {
      fragment_key.stream_id = searchConnection->second.request_stream_id;
    } else {
      fragment_key.stream_id = searchConnection->second.response_stream_id;
    }
    if (searchConnection->second.fragment_map != nullptr) {
      if (auto searchFragments = searchConnection->second.fragment_map->find(fragment_key); searchFragments
          != searchConnection->second.fragment_map->end()) {
        fragments = &searchFragments->second;
        fragmented = !fragments->empty();
      }
    }
  }

  ParseResult parse_result;
  const uint8_t *tcp_stream_data = httpData->tcp_stream_data->getData();

  const uint8_t *fragment_data;
  std::size_t fragment_len;
  std::size_t index = 0;
  while (index < tcpDataLength) {
    if (fragmented) { // there is ongoing fragmented request we're need to add new data to it
      auto old_size = fragments->size();
      fragments->insert(fragments->end(),
                        tcp_stream_data,
                        tcp_stream_data + tcpDataLength);
      fragment_data = fragments->data();
      fragment_len = fragments->size();
      parse_result = http_parser.parse(fragments->data(), fragments->size(), httpData->side);
      parse_result.parsed_bytes -= old_size; // adjust to include only incoming bytes
    } else {
      fragment_data = tcp_stream_data;
      fragment_len = tcpDataLength;
      parse_result = http_parser.parse(tcp_stream_data, tcpDataLength, httpData->side);
    }
    if (parse_result.fragmented) {
      index = tcpDataLength;
      if (!fragmented) { // first fragment, need to add to vector, if not first should be already added
        searchConnection->second.fragment_map = std::make_unique<FragmentsMap>();
        searchConnection->second.fragment_map->insert({fragment_key,
                                                       std::vector<uint8_t>(fragment_data,
                                                                            fragment_data + fragment_len)});
      }
    } else {
      tcpDataLength -= parse_result.parsed_bytes;
      tcp_stream_data += parse_result.parsed_bytes;
      index += parse_result.parsed_bytes;
      if (fragmented) { // all fragments gathered, need to clean up
        searchConnection->second.fragment_map->erase(fragment_key);
      }
      fragmented = false;
      if (httpData->side == HTTP_REQUEST) {
        searchConnection->second.request_stream_id++;
      } else {
        searchConnection->second.response_stream_id++;
      }
      HttpFilterData data {connectionData, HttpInfo{std::move(parse_result.request), fragment_key.stream_id, httpData->side}};
      pass_next(std::make_unique<Data>(Data{HTTP_FILTER_TYPE, reinterpret_cast<void *>(&data)}));
    }
  }
}
void HttpReassembly::connection_closed(const pcpp::ConnectionData &connectionData) {
  fragment_map_.erase(Connection{
      connectionData.srcPort,
      connectionData.srcIP,
      connectionData.dstPort,
      connectionData.dstIP
  });
}
}