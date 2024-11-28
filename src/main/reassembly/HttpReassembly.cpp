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

namespace sniff_my_shit {

// There might be two cases or even both of them:
// 1. Http fragmented in a way that packet here won't contain complete HTTP entity
// 2. Http fragmented in a way that packet will contain multiple http entities
void HttpReassembly::handle(std::unique_ptr<Data> data) {
  if (data->type != HTTP_REASSEMBLY_TYPE) {
    throw std::runtime_error("Unexpected data type in HTTP handle: " + std::to_string(data->type));
  }

  auto *http_data = static_cast<HttpReassemblyData *>(data->payload);
  size_t tcp_data_length = http_data->tcp_stream_data->getDataLength();

  auto connection = http_data->tcp_stream_data->getConnectionData();
  sniff_my_shit::Connection connection_data{
      connection.srcPort,
      connection.srcIP,
      connection.dstPort,
      connection.dstIP
  };

  bool fragmented = false;
  auto search_connection = fragment_map_.find(connection_data);
  std::vector<uint8_t> *fragments = nullptr;
  FragmentKey fragment_key{.stream_id=0, .side=http_data->side};
  if (search_connection == fragment_map_.end()) {
    fragment_map_.insert({connection_data, ConnectionInfo{.request_stream_id=0, .response_stream_id=0, .fragment_map=std::unique_ptr<FragmentsMap>(nullptr)}});
    search_connection = fragment_map_.find(connection_data);
  } else {
    if (http_data->side == HTTP_REQUEST) {
      fragment_key.stream_id = search_connection->second.request_stream_id;
    } else {
      fragment_key.stream_id = search_connection->second.response_stream_id;
    }
    if (search_connection->second.fragment_map != nullptr) {
      if (auto search_fragments = search_connection->second.fragment_map->find(fragment_key); search_fragments
          != search_connection->second.fragment_map->end()) {
        fragments = &search_fragments->second;
        fragmented = !fragments->empty();
      }
    }
  }

  ParseResult parse_result;
  const uint8_t *tcp_stream_data = http_data->tcp_stream_data->getData();

  const uint8_t *fragment_data;
  std::size_t fragment_len;
  std::size_t index = 0;
  while (index < tcp_data_length) {
    if (fragmented) { // there is ongoing fragmented request we're need to add new data to it
      auto old_size = fragments->size();
      fragments->insert(fragments->end(),
                        tcp_stream_data,
                        tcp_stream_data + tcp_data_length);
      parse_result = http_parser_.parse(fragments->data(), fragments->size(), http_data->side);
      parse_result.parsed_bytes -= old_size; // adjust to include only incoming bytes
    } else {
      fragment_data = tcp_stream_data;
      fragment_len = tcp_data_length;
      parse_result = http_parser_.parse(tcp_stream_data, tcp_data_length, http_data->side);
    }
    if (parse_result.fragmented) {
      index = tcp_data_length;
      if (!fragmented) { // first fragment, need to add to vector, if not first should be already added
        search_connection->second.fragment_map = std::make_unique<FragmentsMap>();
        search_connection->second.fragment_map->insert({fragment_key,
                                                        std::vector<uint8_t>(fragment_data,
                                                                             fragment_data + fragment_len)});
      }
    } else {
      tcp_data_length -= parse_result.parsed_bytes;
      tcp_stream_data += parse_result.parsed_bytes;
      index += parse_result.parsed_bytes;
      if (fragmented) { // all fragments gathered, need to clean up
        search_connection->second.fragment_map->erase(fragment_key);
      }
      fragmented = false;
      if (http_data->side == HTTP_REQUEST) {
        search_connection->second.request_stream_id++;
      } else {
        search_connection->second.response_stream_id++;
      }
      HttpFilterData http_filter_data
          {.connection=connection_data, .http_info=HttpInfo{.entity=std::move(parse_result.request), .stream_id=fragment_key.stream_id, .side=http_data->side}};
      pass_next(std::make_unique<Data>(Data{.type=HTTP_FILTER_TYPE, .payload=reinterpret_cast<void *>(&http_filter_data)}));
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