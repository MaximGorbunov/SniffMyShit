#include "httpFilter.h"
#include <iostream>

void SniffMyShit::HttpFilter::handle(std::unique_ptr<Data> data) {
  if (data->type != HTTP_FILTER_TYPE) {
    throw std::runtime_error("Unexpected data type in HTTP filter: " + std::to_string(data->type));
  }
  auto httpData = static_cast<HttpFilterData *>(data->payload);
  std::unordered_map<uint32_t, std::unique_ptr<HttpEntity>> *requests_map = nullptr;
  if (auto requestsMapSearch = requests_.find(httpData->connection); requestsMapSearch != requests_.end()) {
    requests_map = &requestsMapSearch->second;
  } else {
    requests_.insert({httpData->connection, std::unordered_map<uint32_t, std::unique_ptr<HttpEntity>>()});
    requests_map = &requests_[httpData->connection];
  }
  if (httpData->http_info.side == HTTP_REQUEST) {
    // check if fit
    auto request = dynamic_cast<HttpRequest*>(httpData->http_info.entity.get());
    bool fit = std::all_of(request_url_filters->begin(), request_url_filters->end(), [request](const std::string &filter){
      return request->path.find(filter) != std::string::npos;
    });
    fit = fit && std::all_of(request_headers_filters->begin(), request_headers_filters->end(), [request](const std::pair<std::string, std::string> &filter){
      if (auto headerSearch = request->headers.find(filter.first); headerSearch != request->headers.end()) {
        return headerSearch->second.find(filter.second) != std::string::npos;
      }
      return false;
    });
    fit = fit && std::all_of(request_body_filters->begin(), request_body_filters->end(), [request](std::string filter){
      return request->body.find(filter) != std::string::npos;
    });
    if (fit) {
      requests_map->insert({httpData->http_info.stream_id, std::move(httpData->http_info.entity)});
    }
  } else {
    if (auto requestSearch = requests_map->find(httpData->http_info.stream_id); requestSearch != requests_map->end()) {
      auto request = requestSearch->second.get();
      auto response = dynamic_cast<HttpResponse*>(httpData->http_info.entity.get());
      bool fit = std::all_of(response_status_filters->begin(), response_status_filters->end(), [response](const std::string &filter){
        return response->status_code.find(filter) != std::string::npos;
      });
      fit = fit && std::all_of(response_headers_filters->begin(), response_headers_filters->end(), [response](const std::pair<std::string, std::string> &filter){
        if (auto headerSearch = response->headers.find(filter.first); headerSearch != response->headers.end()) {
          return headerSearch->second.find(filter.second) != std::string::npos;
        }
        return false;
      });
      fit = fit && std::all_of(response_body_filters->begin(), response_body_filters->end(), [response](std::string filter){
        return response->body.find(filter) != std::string::npos;
      });
      if (fit) {
        print_request_response(request, httpData->http_info.entity.get());
      }
      requests_map->erase(requestSearch);
    }
  }
}

void SniffMyShit::HttpFilter::connection_closed(const pcpp::ConnectionData &connectionData) {
  requests_.erase(Connection{
      connectionData.srcPort,
      connectionData.srcIP,
      connectionData.dstPort,
      connectionData.dstIP,
  });
}

void print_init_row(const HttpEntity *entity) {
  if (auto request = dynamic_cast<const HttpRequest *>(entity); request != nullptr) {
    std::cout << request->method << " " << request->path << " HTTP " << std::endl;
  } else {
    auto response = dynamic_cast<const HttpResponse *>(entity);
    std::cout << "HTTP " << response->status_code << " " << response->status_text << std::endl;
  }
}

void print_headers(const HttpEntity *entity) {
  for (const auto &header : entity->headers) {
    std::cout << header.first << ": " << header.second << std::endl;
  }
}

void SniffMyShit::HttpFilter::print_request_response(const HttpEntity *request, const HttpEntity *response) {
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