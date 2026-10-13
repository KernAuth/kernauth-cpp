#pragma once

#include "kernauth/version.hpp"

#include <stdexcept>
#include <string>
#include <string_view>

namespace kernauth {

struct EntitlementFields {
  int protocol_version = kProtocolVersion;
  std::string entitlement_id;
  std::string application_id;
  std::string license_id;
  std::string status;
  std::string features;
  std::string device_id;
  std::string issued_at;
  std::string expires_at;
  std::string server_time;
  std::string nonce;
  std::string key_id;
};

class CanonicalError : public std::invalid_argument {
 public:
  explicit CanonicalError(const std::string& message) : std::invalid_argument(message) {}
};

/** Compact canonical JSON: sorted object keys and no extra whitespace. */
std::string canonical_json_text(std::string_view json_text);

/**
 * Canonical entitlement bytes, version 1.
 * UTF-8 `name=value` lines in the Worker field order. Every line ends with LF,
 * including the last line. `features` must already be canonical JSON.
 */
std::string encode_entitlement(const EntitlementFields& fields);

/** Parse bytes produced by `encode_entitlement`. */
bool parse_entitlement(std::string_view canonical, EntitlementFields& fields);

}  // namespace kernauth
