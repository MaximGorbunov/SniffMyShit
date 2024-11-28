#ifndef SNIFFMYSHIT_SRC_MAIN_REASSEMBLY_HTTP_HTTP_H_
#define SNIFFMYSHIT_SRC_MAIN_REASSEMBLY_HTTP_HTTP_H_
#include <string>
#include <unordered_map>

namespace sniff_my_shit {
struct HttpEntity {
  std::unordered_map<std::string, std::string> headers;
  std::string body;
  virtual ~HttpEntity() = default;
};

struct HttpRequest : HttpEntity {
  std::string method;
  std::string path;
  bool fit_filter;
};

struct HttpResponse : HttpEntity {
  std::string status_code;
  std::string status_text;
  bool fit_filter;
};
}
#endif //SNIFFMYSHIT_SRC_MAIN_REASSEMBLY_HTTP_HTTP_H_
