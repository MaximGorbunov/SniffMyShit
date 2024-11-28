#ifndef SNIFFMYSHIT_SRC_MAIN_REASSEMBLY_PARSER_PROTOCOLPARSER_H_
#define SNIFFMYSHIT_SRC_MAIN_REASSEMBLY_PARSER_PROTOCOLPARSER_H_
#include <cinttypes>
#include <memory>
#include "../http/http.h"

#ifndef HTTP_REQUEST
#define HTTP_REQUEST   0
#endif

#ifndef HTTP_RESPONSE
#define HTTP_RESPONSE  1
#endif

namespace sniff_my_shit {
struct ParseResult {
  uint64_t parsed_bytes;
  bool fragmented;
  std::unique_ptr<HttpEntity> request;
};

class ProtocolParser {
 public:
  ProtocolParser() = default;
  virtual ~ProtocolParser() = default;
  virtual ParseResult parse(const uint8_t *data, std::size_t len, int8_t side) = 0;
};
}
#endif //SNIFFMYSHIT_SRC_MAIN_REASSEMBLY_PARSER_PROTOCOLPARSER_H_
