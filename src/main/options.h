#ifndef SNIFFMYSHIT_SRC_MAIN_OPTIONS_H_
#define SNIFFMYSHIT_SRC_MAIN_OPTIONS_H_

#include <string>
#include <getopt.h>
#include <memory>
#include <vector>
#include <unordered_map>

namespace SniffMyShit {
#ifdef __APPLE__
static const char *const short_options = "i:t:p:u:S:h:H:b:B:";
#else
static const char *const short_options = "i:t:p:u:S:h:H:b:B:";
#endif

// @formatter:off
[[maybe_unused]]static struct option Options[] = {
    { "interface",      optional_argument, nullptr, 'i' },
    { "time",           optional_argument, nullptr, 't' },
    { "request-url",           optional_argument, nullptr, 'u' },
    { "response-status",           optional_argument, nullptr, 'S' },
    { "request-header",           optional_argument, nullptr, 'h' },
    { "response-header",           optional_argument, nullptr, 'H' },
    { "request-body",           optional_argument, nullptr, 'b' },
    { "response-body",           optional_argument, nullptr, 'B' },
    { nullptr,          0,               nullptr,    0   }
};
    // @formatter:on

    struct ParsedOptions {
        std::string interface;
        uint32_t time;
        uint16_t port;
        std::vector<std::string> request_url_filters;
        std::unordered_map<std::string, std::string> request_headers_filters;
        std::vector<std::string> request_body_filters;
        std::vector<std::string> response_status_filters;
        std::unordered_map<std::string, std::string> response_headers_filters;
        std::vector<std::string> response_body_filters;
    };

    std::unique_ptr<ParsedOptions> parseOptions(int argc, char *argv[]);
}
#endif //SNIFFMYSHIT_SRC_MAIN_OPTIONS_H_
