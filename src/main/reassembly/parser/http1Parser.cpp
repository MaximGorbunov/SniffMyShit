#include "http1Parser.h"

#include <algorithm>
#include <iostream>
#include <memory>

using std::unique_ptr, std::make_unique, std::size_t, std::string,
    std::tolower, sniff_my_shit::ParseResult, sniff_my_shit::HttpRequest,
    sniff_my_shit::HttpEntity, sniff_my_shit::HttpResponse;

namespace {
ParseResult parse_http1_request(const char *data, size_t length) {
  auto request = make_unique<HttpRequest>();
  size_t start = 0;
  enum part { kMethod, kUrl, kVersion, kHeaders, kBody };
  int current_part = kMethod;
  string key;
  string value;
  size_t i = 0;

  // read initial row
  while (i < length - 1 && data[i] != '\r' && data[i + 1] != '\n') {
    if (current_part == kMethod && data[i] == ' ') {
      request->method = string(data + start, i - start);
      current_part++;
      start = i + 1;
    } else if (current_part == kUrl && data[i] == ' ') {
      request->path = string(&data[start], i - start);
    }
    ++i;
  }
  i += 2; // since we end at \r\n
  start = i;

  // read headers
  while (i < length - 3 && (data[i] != '\r' || data[i + 1] != '\n'
      || data[i + 2] != '\r' || data[i + 3] != '\n')) {
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
  size_t expected_length = 0;
  if (auto transfer_encoding_header_search = request->headers.find("transfer-encoding"); transfer_encoding_header_search
      != request->headers.end()) {
    if (transfer_encoding_header_search->second == "chunked") {
      //iterate over each chunk
      size_t chunk_hex_start = start;
      while (i < length - 1 && (data[i] == '\r' || data[i + 1] == '\n' || data[i + 2] != '0' || data[i + 3] == '\r'
          || data[i + 4] == '\n')) {
        while (i < length - 1 && data[i] != '\r' && data[i + 1] != '\n') { i++; }
        if (i >= length - 1) {
          return ParseResult{.parsed_bytes=0, .fragmented=true, .request=unique_ptr<HttpEntity>(nullptr)};
        }
        expected_length = stoi(string(&data[chunk_hex_start], i - chunk_hex_start), nullptr, 16);
        i += 4 + expected_length;
        chunk_hex_start = i;

      }
      if (data[i - 5] == '0' && data[i - 4] == '\r' && data[i - 3] == '\n' && data[i - 2] == '\r'
          && data[i - 1] == '\n') {
        request->body = string(&data[start], i - start);
        return ParseResult{.parsed_bytes=i, .fragmented=false, .request=std::move(request)};
      }
      return ParseResult{.parsed_bytes=0, .fragmented=true, .request=std::unique_ptr<HttpEntity>(nullptr)};
    }
  }

  //read body
  auto content_length_search = request->headers.find("content-length");
  if (content_length_search != request->headers.end()) {
    expected_length = stoi(content_length_search->second);
    if (length - start < expected_length) { //Not enough data to parse whole body
      return ParseResult{.parsed_bytes=0, .fragmented=true, .request=unique_ptr<HttpEntity>(nullptr)};
    }
    request->body = string(&data[start], expected_length);
    return ParseResult{
        .parsed_bytes=static_cast<uint64_t>(&data[start + expected_length] - data),
        .fragmented=false,
        .request=std::move(request)
    };

  }
  if (data[i - 4] == '\r' && data[i - 3] == '\n' && data[i - 2] == '\r'
      && data[i - 1] == '\n') { //No body expected
    return ParseResult{.parsed_bytes=i, .fragmented=false, .request=std::move(request)};
  }
  // Message doesn't end with \r\n\r\n means message fragmented
  return ParseResult{.parsed_bytes=0, .fragmented=true, .request=unique_ptr<HttpEntity>(nullptr)};
}

ParseResult parse_http1_response(const char *data, size_t length) {
  //parse method
  auto response = make_unique<HttpResponse>();
  size_t start = 0;
  enum part { kProtocol, kStatusCode, kStatusText, kHeaders, kBody };
  int current_part = kProtocol;
  string key;
  string value;
  size_t i = 0;

  // read initial row
  while (i < length - 1 && data[i] != '\r' && data[i + 1] != '\n') {
    if (current_part == kProtocol && data[i] == ' ') {
      current_part++;
      start = i + 1;
    } else if (current_part == kStatusCode && data[i] == ' ') {
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
  while (i < length - 3 && (data[i] != '\r' || data[i + 1] != '\n'
      || data[i + 2] != '\r' || data[i + 3] != '\n')) {
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

  size_t expected_length = 0;

  //chunked encoding support
  if (auto transfer_encoding_header_search = response->headers.find("transfer-encoding");
      transfer_encoding_header_search
          != response->headers.end()) {
    if (transfer_encoding_header_search->second == "chunked") {
      //iterate over each chunk
      size_t chunk_hex_start = start;
      while (i < length - 1 && (data[i] == '\r' || data[i + 1] == '\n' || data[i + 2] != '0' || data[i + 3] == '\r'
          || data[i + 4] == '\n')) {
        while (i < length - 1 && data[i] != '\r' && data[i + 1] != '\n') { i++; }
        if (i >= length - 1) {
          return ParseResult{.parsed_bytes=0, .fragmented=true, .request=unique_ptr<HttpEntity>(nullptr)};
        }
        expected_length = stoi(string(&data[chunk_hex_start], i - chunk_hex_start), nullptr, 16);
        i += 4 + expected_length;
        chunk_hex_start = i;

      }
      if (data[i - 5] == '0' && data[i - 4] == '\r' && data[i - 3] == '\n' && data[i - 2] == '\r'
          && data[i - 1] == '\n') {
        response->body = string(&data[start], i - start);
        return ParseResult{.parsed_bytes=i, .fragmented=false, .request=std::move(response)};
      }
      return ParseResult{.parsed_bytes=0, .fragmented=true, .request=std::unique_ptr<HttpEntity>(nullptr)};
    }
  }

  //read body
  auto content_length_search = response->headers.find("content-length");
  if (content_length_search != response->headers.end()) {
    expected_length = stoi(content_length_search->second);
  }
  if (expected_length > 0) {
    if (length - start < expected_length) { //Not enough data to parse whole body
      return ParseResult{.parsed_bytes=0, .fragmented=true, .request=unique_ptr<HttpEntity>(nullptr)};
    }
    response->body = string(&data[start], expected_length);
    return ParseResult{
        .parsed_bytes=static_cast<uint64_t>(&data[start + expected_length] - data),
        .fragmented=false,
        .request=std::move(response)
    };

  }
  if (data[i - 4] == '\r' && data[i - 3] == '\n' && data[i - 2] == '\r'
      && data[i - 1] == '\n') { //No body expected
    return ParseResult{.parsed_bytes=i, .fragmented=false, .request=std::move(response)};
  }
  // Message doesn't end with \r\n\r\n means message fragmented
  return ParseResult{.parsed_bytes=0, .fragmented=true, .request=unique_ptr<HttpEntity>(nullptr)};

}
}

ParseResult sniff_my_shit::Http1Parser::parse(const uint8_t *data, size_t len, int8_t side) {
  if (side == HTTP_REQUEST) {
    return parse_http1_request(reinterpret_cast<const char *>(data), len);
  }
  return parse_http1_response(reinterpret_cast<const char *>(data), len);

}