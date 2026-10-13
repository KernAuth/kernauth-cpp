#include "kernauth/http.hpp"

#include <curl/curl.h>

#include <stdexcept>

namespace kernauth {
namespace {

struct WriteBuffer {
  std::string body;
};

std::size_t write_body(char* pointer, std::size_t size, std::size_t count, void* userdata) {
  const std::size_t bytes = size * count;
  auto* buffer = static_cast<WriteBuffer*>(userdata);
  buffer->body.append(pointer, bytes);
  return bytes;
}

void ensure_curl() {
  static const CURLcode ready = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (ready != CURLE_OK) {
    throw std::runtime_error("libcurl failed to initialize");
  }
}

}  // namespace

HttpResponse CurlTransport::exchange(const HttpRequest& request) {
  HttpResponse response;
  try {
    ensure_curl();
  } catch (const std::exception&) {
    response.transport_error = "libcurl failed to initialize";
    return response;
  }

  CURL* curl = curl_easy_init();
  if (curl == nullptr) {
    response.transport_error = "libcurl could not start a request";
    return response;
  }

  WriteBuffer buffer;
  char error_buffer[CURL_ERROR_SIZE] = {};
  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "Accept: application/json");

  curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "kernauth-sdk/0.4.0");
  if (request.method == "POST") {
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
  } else {
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  }

  const CURLcode code = curl_easy_perform(curl);
  if (code != CURLE_OK) {
    response.transport_error = error_buffer[0] == '\0' ? curl_easy_strerror(code) : error_buffer;
  } else {
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    response.status = static_cast<int>(status);
    response.body = std::move(buffer.body);
  }

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  return response;
}

}  // namespace kernauth
