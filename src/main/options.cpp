#include "options.h"
#include <algorithm>

using sniff_my_shit::ParsedOptions, std::ranges::transform;

std::unique_ptr<ParsedOptions> sniff_my_shit::parseOptions(int argc, char *argv[]) {
  int option_index = 0;
  int opt;
  auto parsed_options = std::make_unique<ParsedOptions>(ParsedOptions{});
  parsed_options->time = 10;
  while ((opt = getopt_long(argc, argv, kShortOptions, options, &option_index)) != -1) {
    switch (opt) {
      case 'i':
        if (optarg != nullptr) {
          parsed_options->interface = optarg;
        }
        break;
      case 't':
        if (optarg != nullptr) {
          parsed_options->time = std::strtol(optarg, nullptr, 10);
        } else {
          parsed_options->time = 10;
        }
        break;
      case 'p':
        if (optarg == nullptr) {
          throw std::runtime_error("Usage: -i lo0 -t 100 -p 8080");
        }
        parsed_options->port = static_cast<uint16_t>(std::strtol(optarg, nullptr, 10));
        break;
      case 'u':
        if (optarg != nullptr) {
          parsed_options->request_url_filters.emplace_back(optarg);
        }
        break;
      case 'h':
        if (optarg != nullptr) {
          auto header = std::string(optarg);
          auto delimiter = header.find(':');
          if (delimiter != std::string::npos) {
            auto key = header.substr(0, delimiter);
            auto value = header.substr(delimiter + 1);
            transform(key.begin(), key.end(), key.begin(),
                      [](unsigned char c) { return tolower(c); });
            transform(value.begin(), value.end(), value.begin(),
                      [](unsigned char c) { return tolower(c); });
            parsed_options->request_headers_filters.insert({key, value});
          } else {
            throw std::runtime_error("Incorrect header format. Expected K:V");
          }
        }
        break;
      case 'b':
        if (optarg != nullptr) {
          parsed_options->request_body_filters.emplace_back(optarg);
        }
        break;
      case 'S':
        if (optarg != nullptr) {
          parsed_options->response_status_filters.emplace_back(optarg);
        }
        break;
      case 'H':
        if (optarg != nullptr) {
          auto header = std::string(optarg);
          auto delimiter = header.find(':');
          if (delimiter != std::string::npos) {
            auto key = header.substr(0, delimiter);
            auto value = header.substr(delimiter + 1);
            transform(key.begin(), key.end(), key.begin(),
                      [](unsigned char c) { return tolower(c); });
            transform(value.begin(), value.end(), value.begin(),
                      [](unsigned char c) { return tolower(c); });
            parsed_options->response_headers_filters.insert({key, value});
          } else {
            throw std::runtime_error("Incorrect header format. Expected K:V");
          }
        }
        break;
      case 'B':
        if (optarg != nullptr) {
          parsed_options->response_body_filters.emplace_back(optarg);
        }
        break;
      default: throw std::runtime_error("Usage: -i lo0 -t 100 -p 8080");
    }
  }
  return parsed_options;
}