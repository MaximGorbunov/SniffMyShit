#include "httpFilter.h"
#include <iostream>

void sniff_my_shit::HttpFilter::handle(std::unique_ptr<Data> data) {
  if (data->type != HTTP_FILTER_TYPE) {
    throw std::runtime_error("Unexpected data type in HTTP filter: " + std::to_string(data->type));
  }
  auto *http_data = static_cast<HttpFilterData *>(data->payload);
  std::unordered_map<uint32_t, std::unique_ptr<HttpEntity>> *requests_map = nullptr;
  if (auto requests_map_search = requests_.find(http_data->connection); requests_map_search != requests_.end()) {
    requests_map = &requests_map_search->second;
  } else {
    requests_.insert({http_data->connection, std::unordered_map<uint32_t, std::unique_ptr<HttpEntity>>()});
    requests_map = &requests_[http_data->connection];
  }
  if (http_data->http_info.side == HTTP_REQUEST) {
    // check if fit
    auto *request = dynamic_cast<HttpRequest *>(http_data->http_info.entity.get());
    bool fit = std::ranges::all_of(*request_url_filters_, [request](const std::string &filter) {
      return request->path.find(filter) != std::string::npos;
    });
    fit = fit
        && std::ranges::all_of(*request_headers_filters_, [request](const std::pair<std::string, std::string> &filter) {
          if (auto header_search = request->headers.find(filter.first); header_search != request->headers.end()) {
            return header_search->second.find(filter.second) != std::string::npos;
          }
          return false;
        });
    fit = fit && std::ranges::all_of(*request_body_filters_, [request](const std::string &filter) {
      return request->body.find(filter) != std::string::npos;
    });
    if (fit) {
      requests_map->insert({http_data->http_info.stream_id, std::move(http_data->http_info.entity)});
    }
  } else {
    if (auto request_search = requests_map->find(http_data->http_info.stream_id); request_search
        != requests_map->end()) {
      auto *request = request_search->second.get();
      auto *response = dynamic_cast<HttpResponse *>(http_data->http_info.entity.get());
      bool fit = std::ranges::all_of(*response_status_filters, [response](const std::string &filter) {
        return response->status_code.find(filter) != std::string::npos;
      });
      fit = fit && std::ranges::all_of(*response_headers_filters,
                                       [response](const std::pair<std::string, std::string> &filter) {
                                         if (auto header_search = response->headers.find(filter.first); header_search
                                             != response->headers.end()) {
                                           return header_search->second.find(filter.second) != std::string::npos;
                                         }
                                         return false;
                                       });
      fit = fit && std::ranges::all_of(*response_body_filters, [response](const std::string &filter) {
        return response->body.find(filter) != std::string::npos;
      });
      if (fit) {
        print_request_response(request, http_data->http_info.entity.get());
      }
      requests_map->erase(request_search);
    }
  }
}

void sniff_my_shit::HttpFilter::connection_closed(const pcpp::ConnectionData &connectionData) {
  requests_.erase(Connection{
      connectionData.srcPort,
      connectionData.srcIP,
      connectionData.dstPort,
      connectionData.dstIP,
  });
}

namespace {
void print_init_row(const sniff_my_shit::HttpEntity *entity) {
  if (const auto *request = dynamic_cast<const sniff_my_shit::HttpRequest *>(entity); request != nullptr) {
    std::cout << request->method << " " << request->path << " HTTP " << std::endl;
  } else {
    const auto *response = dynamic_cast<const sniff_my_shit::HttpResponse *>(entity);
    std::cout << "HTTP " << response->status_code << " " << response->status_text << std::endl;
  }
}

void print_headers(const sniff_my_shit::HttpEntity *entity) {
  for (const auto &header : entity->headers) {
    std::cout << header.first << ": " << header.second << std::endl;
  }
}
}

void sniff_my_shit::HttpFilter::print_request_response(const HttpEntity *request, const HttpEntity *response) {
  std::cout << "====================REQUEST====================" << std::endl;
  print_init_row(request);
  print_headers(request);
  std::cout << request->body << std::endl;
  std::cout << "================================================" << std::endl;
  std::cout << "====================RESPONSE====================" << std::endl;
  print_init_row(response);
  print_headers(response);
  std::cout << response->body << std::endl;
  std::cout << "================================================" << std::endl;

}