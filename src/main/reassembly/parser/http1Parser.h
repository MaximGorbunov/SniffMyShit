#ifndef SNIFFMYSHIT_SRC_MAIN_REASSEMBLY_PARSER_HTTP1PARSER_H_
#define SNIFFMYSHIT_SRC_MAIN_REASSEMBLY_PARSER_HTTP1PARSER_H_
#include "protocolParser.h"
namespace SniffMyShit {
class Http1Parser : ProtocolParser {
 public:
  ParseResult parse(const uint8_t *data, std::size_t len, int8_t side) override;
};
}
#endif //SNIFFMYSHIT_SRC_MAIN_REASSEMBLY_PARSER_HTTP1PARSER_H_
