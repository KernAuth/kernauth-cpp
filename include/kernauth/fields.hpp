#pragma once

#include "kernauth/version.hpp"

#include <string>

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

}  // namespace kernauth
