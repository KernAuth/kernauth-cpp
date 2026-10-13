#pragma once

#include <string>

namespace kernauth {

struct HttpRequest {
  std::string method;
  std::string url;
  std::string body;
};

struct HttpResponse {
  int status = 0;
  std::string body;
  std::string transport_error;
};

class HttpTransport {
 public:
  virtual ~HttpTransport() = default;
  virtual HttpResponse exchange(const HttpRequest& request) = 0;
};

/** libcurl transport used by the console example. Tests supply their own transport. */
class CurlTransport final : public HttpTransport {
 public:
  HttpResponse exchange(const HttpRequest& request) override;
};

}  // namespace kernauth
