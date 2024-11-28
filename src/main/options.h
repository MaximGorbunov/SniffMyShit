#ifndef SNIFFMYSHIT_SRC_MAIN_OPTIONS_H_
#define SNIFFMYSHIT_SRC_MAIN_OPTIONS_H_

#include <string>
#include <getopt.h>
#include <memory>
#include <vector>
#include <unordered_map>

namespace sniff_my_shit {
#ifdef __APPLE__
static const char *const kShortOptions = "i:t:p:u:S:h:H:b:B:";
#else
static const char *const kShortOptions = "i:t:p:u:S:h:H:b:B:";
#endif

// @formatter:off
[[maybe_unused]]static struct option options[] = {
    { .name="interface",          .has_arg=optional_argument, .flag=nullptr, .val='i' },
    { .name="time",               .has_arg=optional_argument, .flag=nullptr, .val='t' },
    { .name="request-url",        .has_arg=optional_argument, .flag=nullptr, .val='u' },
    { .name="response-status",    .has_arg=optional_argument, .flag=nullptr, .val='S' },
    { .name="request-header",     .has_arg=optional_argument, .flag=nullptr, .val='h' },
    { .name="response-header",    .has_arg=optional_argument, .flag=nullptr, .val='H' },
    { .name="request-body",       .has_arg=optional_argument, .flag=nullptr, .val='b' },
    { .name="response-body",      .has_arg=optional_argument, .flag=nullptr, .val='B' },
    { .name=nullptr,              .has_arg=0,                 .flag=nullptr, .val=0   }
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
