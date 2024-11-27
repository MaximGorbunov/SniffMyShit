#include "http1Parser.h"

#include <algorithm>
#include <iostream>
#include <memory>

using std::unique_ptr, std::make_unique, std::size_t, std::string, std::isprint, std::stoi, std::transform,
    std::tolower, std::runtime_error, SniffMyShit::ParseResult;

ParseResult parse_http1_request(const char *data, size_t length) {
  auto request = make_unique<HttpRequest>();
  size_t start = 0;
  enum part { method, url, version, headers, body };
  int current_part = method;
  string key, value;
  size_t i = 0;

  // read initial row
  while (i < length - 1 && data[i] != '\r' && data[i + 1] != '\n') {
    if (current_part == method && data[i] == ' ') {
      request->method = string(data + start, i - start);
      current_part++;
      start = i + 1;
    } else if (current_part == url && data[i] == ' ') {
      request->path = string(&data[start], i - start);
    }
    ++i;
  }
  i += 2; // since we end at \r\n
  start = i;

  // read headers
  while (i < length - 3 && !(data[i] == '\r' && data[i + 1] == '\n'
      && data[i + 2] == '\r' && data[i + 3] == '\n')) {
    if (data[i] == ':' && key.empty()) {
      key = string(&data[start], i - start); // Also minus :
      std::ranges::transform(key, key.begin(),
                             [](unsigned char c) { return tolower(c); });
      start = i + 2;
    } else if (data[i] == '\r' && data[i + 1] == '\n') {
      value = string(&data[start], i - start);
      std::ranges::transform(value, value.begin(),
                             [](unsigned char c) { return tolower(c); });
      request->headers[key] = value;
      key = "";
      start = i + 2;
    }
    ++i;
  }
  // add last header
  value = string(&data[start], i - start);
  std::ranges::transform(value, value.begin(),
                         [](unsigned char c) { return tolower(c); });
  request->headers[key] = value;
  i += 4; // since we end at \r\n\r\n
  start = i;

  //chunked encoding support
  size_t expectedLength = 0;
  if (auto transferEncodingHeaderSearch = request->headers.find("transfer-encoding"); transferEncodingHeaderSearch
      != request->headers.end()) {
    if (transferEncodingHeaderSearch->second == "chunked") {
      //iterate over each chunk
      size_t chunk_hex_start = start;
      while (i < length - 1 && !(data[i] != '\r' && data[i + 1] != '\n' && data[i + 2] == '0' && data[i + 3] != '\r'
          && data[i + 4] != '\n')) {
        while (i < length - 1 && data[i] != '\r' && data[i + 1] != '\n') { i++; }
        if (i >= length - 1) {
          return ParseResult{0, true, unique_ptr<HttpEntity>(nullptr)};
        } else {
          expectedLength = stoi(string(&data[chunk_hex_start], i - chunk_hex_start), nullptr, 16);
          i += 4 + expectedLength;
          chunk_hex_start = i;
        }
      }
      if (data[i - 5] == '0' && data[i - 4] == '\r' && data[i - 3] == '\n' && data[i - 2] == '\r'
          && data[i - 1] == '\n') {
        request->body = string(&data[start], i - start);
        return ParseResult{i, false, std::move(request)};
      } else {
        return ParseResult{0, true, std::unique_ptr<HttpEntity>(nullptr)};
      }
    }
  }

  //read body
  auto contentLengthSearch = request->headers.find("content-length");
  if (contentLengthSearch != request->headers.end()) {
    expectedLength = stoi(contentLengthSearch->second);
    if (length - start < expectedLength) { //Not enough data to parse whole body
      return ParseResult{0, true, unique_ptr<HttpEntity>(nullptr)};
    } else {
      request->body = string(&data[start], expectedLength);
      return ParseResult{
          static_cast<uint64_t>(&data[start + expectedLength] - data),
          false,
          std::move(request)
      };
    }
  } else if (data[i - 4] == '\r' && data[i - 3] == '\n' && data[i - 2] == '\r'
      && data[i - 1] == '\n') { //No body expected
    return ParseResult{i, false, std::move(request)};
  } else { // Message doesn't end with \r\n\r\n means message fragmented
    return ParseResult{0, true, unique_ptr<HttpEntity>(nullptr)};
  }
}

ParseResult parse_http1_response(const char *data, size_t length) {
  //parse method
  auto response = make_unique<HttpResponse>();
  size_t start = 0;
  enum part { protocol, status_code, status_text, headers, body };
  int current_part = protocol;
  string key, value;
  size_t i = 0;

  // read initial row
  while (i < length - 1 && data[i] != '\r' && data[i + 1] != '\n') {
    if (current_part == protocol && data[i] == ' ') {
      current_part++;
      start = i + 1;
    } else if (current_part == status_code && data[i] == ' ') {
      response->status_code = string(data + start, i - start);
      current_part++;
      start = i + 1;
    }
    ++i;
  }
  response->status_text = string(data + start, i - start + 1);
  i += 2; // since we end at \r\n
  start = i;

// read headers
  while (i < length - 3 && !(data[i] == '\r' && data[i + 1] == '\n'
      && data[i + 2] == '\r' && data[i + 3] == '\n')) {
    if (data[i] == ':' && key.empty()) {
      key = string(&data[start], i - start); // Also minus :
      std::ranges::transform(key, key.begin(),
                             [](unsigned char c) { return tolower(c); });
      start = i + 2;
    } else if (data[i] == '\r' && data[i + 1] == '\n') {
      value = string(&data[start], i - start);
      std::ranges::transform(value, value.begin(),
                             [](unsigned char c) { return tolower(c); });
      response->headers[key] = value;
      key = "";
      start = i + 2;
    }
    ++i;
  }
  // add last header
  value = string(&data[start], i - start);
  std::ranges::transform(value, value.begin(),
                         [](unsigned char c) { return tolower(c); });
  response->headers[key] = value;
  i += 4; // since we end at \r\n\r\n
  start = i;

  size_t expectedLength = 0;

  //chunked encoding support
  if (auto transferEncodingHeaderSearch = response->headers.find("transfer-encoding"); transferEncodingHeaderSearch
      != response->headers.end()) {
    if (transferEncodingHeaderSearch->second == "chunked") {
      //iterate over each chunk
      size_t chunk_hex_start = start;
      while (i < length - 1 && !(data[i] != '\r' && data[i + 1] != '\n' && data[i + 2] == '0' && data[i + 3] != '\r'
          && data[i + 4] != '\n')) {
        while (i < length - 1 && data[i] != '\r' && data[i + 1] != '\n') { i++; }
        if (i >= length - 1) {
          return ParseResult{0, true, unique_ptr<HttpEntity>(nullptr)};
        } else {
          expectedLength = stoi(string(&data[chunk_hex_start], i - chunk_hex_start), nullptr, 16);
          i += 4 + expectedLength;
          chunk_hex_start = i;
        }
      }
      if (data[i - 5] == '0' && data[i - 4] == '\r' && data[i - 3] == '\n' && data[i - 2] == '\r'
          && data[i - 1] == '\n') {
        response->body = string(&data[start], i - start);
        return ParseResult{i, false, std::move(response)};
      } else {
        return ParseResult{0, true, std::unique_ptr<HttpEntity>(nullptr)};
      }
    }
  }

  //read body
  auto contentLengthSearch = response->headers.find("content-length");
  if (contentLengthSearch != response->headers.end()) {
    expectedLength = stoi(contentLengthSearch->second);
  }
  if (expectedLength > 0) {
    if (length - start < expectedLength) { //Not enough data to parse whole body
      return ParseResult{0, true, unique_ptr<HttpEntity>(nullptr)};
    } else {
      response->body = string(&data[start], expectedLength);
      return ParseResult{
          static_cast<uint64_t>(&data[start + expectedLength] - data),
          false,
          std::move(response)
      };
    }
  } else if (data[i - 4] == '\r' && data[i - 3] == '\n' && data[i - 2] == '\r'
      && data[i - 1] == '\n') { //No body expected
    return ParseResult{i, false, std::move(response)};
  } else { // Message doesn't end with \r\n\r\n means message fragmented
    return ParseResult{0, true, unique_ptr<HttpEntity>(nullptr)};
  }
}

ParseResult SniffMyShit::Http1Parser::parse(const uint8_t *data, size_t len, int8_t side) {
  if (side == HTTP_REQUEST) {
    return parse_http1_request(reinterpret_cast<const char *>(data), len);
  } else {
    return parse_http1_response(reinterpret_cast<const char *>(data), len);
  }
}