#ifndef SNIFFMYSHIT_SRC_MAIN_FILTER_HTTPFILTER_H_
#define SNIFFMYSHIT_SRC_MAIN_FILTER_HTTPFILTER_H_
#include <memory>
#include "../handler.h"
#include "../reassembly/connection.h"
#include "../reassembly/http/http.h"

#define HTTP_FILTER_TYPE 0x3

#ifndef HTTP_REQUEST
#define HTTP_REQUEST   0
#endif

#ifndef HTTP_RESPONSE
#define HTTP_RESPONSE  1
#endif

namespace SniffMyShit {
struct HttpInfo {
  std::unique_ptr<HttpEntity> entity;
  uint32_t stream_id;
  int8_t side;
};

struct HttpFilterData {
  Connection connection;
  HttpInfo http_info;
};

class HttpFilter : public Handler {
 public:
  HttpFilter(
      std::vector<std::string> *a_request_url_filters,
      std::unordered_map<std::string, std::string> *a_request_headers_filters,
      std::vector<std::string> *a_request_body_filters,
      std::vector<std::string> *a_response_status_filters,
      std::unordered_map<std::string, std::string> *a_response_headers_filters,
      std::vector<std::string> *a_response_body_filters
  ) : Handler(std::unique_ptr<Handler>(nullptr)),
      request_url_filters(a_request_url_filters),
      request_headers_filters(a_request_headers_filters),
      request_body_filters(a_request_body_filters),
      response_status_filters(a_response_status_filters),
      response_headers_filters(a_response_headers_filters),
      response_body_filters(a_response_body_filters) {}
  void handle(std::unique_ptr<Data> data) override;
  void connection_closed(const pcpp::ConnectionData &connectionData) override;
 private:
  std::unordered_map<Connection, std::unordered_map<uint32_t, std::unique_ptr<HttpEntity>>> requests_;
  std::vector<std::string> *request_url_filters;
  std::unordered_map<std::string, std::string> *request_headers_filters;
  std::vector<std::string> *request_body_filters;
  std::vector<std::string> *response_status_filters;
  std::unordered_map<std::string, std::string> *response_headers_filters;
  std::vector<std::string> *response_body_filters;
  void print_request_response(const HttpEntity *request, const HttpEntity *response);
};
}
#endif //SNIFFMYSHIT_SRC_MAIN_FILTER_HTTPFILTER_H_
