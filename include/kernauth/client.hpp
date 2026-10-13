#pragma once

#include "kernauth/canonical.hpp"
#include "kernauth/http.hpp"

#include <functional>
#include <string>
#include <string_view>

namespace kernauth {

struct ClientOptions {
  std::string base_url;
  std::string public_app_id;
  std::string public_key_base64;
  std::string key_id;
  std::string client_version = "0.4.0";
  int fingerprint_version = 1;
  std::string device_fingerprint;
  std::string installation_id;
  std::string device_label;
  std::function<std::string()> nonce_generator;
  std::function<std::string()> now_iso;
};

struct ClientResult {
  bool ok = false;
  bool active = false;
  int http_status = 0;
  std::string code;
  std::string message;
  std::string request_id;
  EntitlementFields entitlement;
  std::string signature_base64;
};

struct VersionInfo {
  bool ok = false;
  int http_status = 0;
  int protocol_version = 0;
  std::string key_id;
  std::string public_key_base64;
  std::string request_id;
  std::string code;
  std::string message;
};

VersionInfo fetch_version(HttpTransport& transport, std::string_view base_url);

ClientResult activate(
    HttpTransport& transport,
    const ClientOptions& options,
    std::string_view license_key);
ClientResult validate_license(
    HttpTransport& transport,
    const ClientOptions& options,
    std::string_view license_key);
ClientResult deactivate(
    HttpTransport& transport,
    const ClientOptions& options,
    std::string_view license_key);

}  // namespace kernauth
