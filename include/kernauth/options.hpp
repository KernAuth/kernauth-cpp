#pragma once

#include "kernauth/fields.hpp"

#include <array>
#include <cstddef>
#include <functional>
#include <string>
#include <vector>

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
  /** From App.initialize() — required when the application has a payload key. */
  std::string session_salt;
  std::string time_bucket;
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

struct PayloadUnwrap {
  bool ok = false;
  std::string payload_key;
  std::string message;
};

struct FileKey {
  std::string name;
  std::array<unsigned char, 32> key{};
};

struct DownloadResult {
  bool ok = false;
  std::string message;
  std::vector<unsigned char> bytes;
};

}  // namespace kernauth
