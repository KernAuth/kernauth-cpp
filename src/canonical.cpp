#include "kernauth/canonical.hpp"

#include <nlohmann/json.hpp>

namespace kernauth {
namespace {

constexpr std::string_view kFieldOrder[] = {
    "protocol_version",
    "entitlement_id",
    "application_id",
    "license_id",
    "status",
    "features",
    "device_id",
    "issued_at",
    "expires_at",
    "server_time",
    "nonce",
    "key_id",
};

bool contains_line_break(std::string_view value) {
  return value.find('\n') != std::string_view::npos || value.find('\r') != std::string_view::npos;
}

std::string field_value(const EntitlementFields& fields, std::string_view name) {
  if (name == "protocol_version") {
    return std::to_string(fields.protocol_version);
  }
  if (name == "entitlement_id") {
    return fields.entitlement_id;
  }
  if (name == "application_id") {
    return fields.application_id;
  }
  if (name == "license_id") {
    return fields.license_id;
  }
  if (name == "status") {
    return fields.status;
  }
  if (name == "features") {
    return fields.features;
  }
  if (name == "device_id") {
    return fields.device_id;
  }
  if (name == "issued_at") {
    return fields.issued_at;
  }
  if (name == "expires_at") {
    return fields.expires_at;
  }
  if (name == "server_time") {
    return fields.server_time;
  }
  if (name == "nonce") {
    return fields.nonce;
  }
  if (name == "key_id") {
    return fields.key_id;
  }
  throw CanonicalError("Unknown entitlement field");
}

}  // namespace

std::string canonical_json_text(std::string_view json_text) {
  try {
    const auto parsed = nlohmann::json::parse(json_text);
    return parsed.dump();
  } catch (const nlohmann::json::exception&) {
    throw CanonicalError("Canonical JSON value is not supported");
  }
}

std::string encode_entitlement(const EntitlementFields& fields) {
  std::string encoded;
  for (const std::string_view name : kFieldOrder) {
    const std::string value = field_value(fields, name);
    if (contains_line_break(value)) {
      throw CanonicalError("Canonical entitlement field contains a line break");
    }
    encoded.append(name);
    encoded.push_back('=');
    encoded.append(value);
    encoded.push_back('\n');
  }
  return encoded;
}

bool parse_entitlement(std::string_view canonical, EntitlementFields& fields) {
  EntitlementFields parsed;
  std::size_t index = 0;
  for (const std::string_view name : kFieldOrder) {
    if (index >= canonical.size()) {
      return false;
    }
    const std::size_t line_end = canonical.find('\n', index);
    if (line_end == std::string_view::npos) {
      return false;
    }
    const std::string_view line = canonical.substr(index, line_end - index);
    const std::string prefix = std::string(name) + "=";
    if (!line.starts_with(prefix)) {
      return false;
    }
    const std::string value(line.substr(prefix.size()));
    if (name == "protocol_version") {
      try {
        parsed.protocol_version = std::stoi(value);
      } catch (const std::exception&) {
        return false;
      }
    } else if (name == "entitlement_id") {
      parsed.entitlement_id = value;
    } else if (name == "application_id") {
      parsed.application_id = value;
    } else if (name == "license_id") {
      parsed.license_id = value;
    } else if (name == "status") {
      parsed.status = value;
    } else if (name == "features") {
      parsed.features = value;
    } else if (name == "device_id") {
      parsed.device_id = value;
    } else if (name == "issued_at") {
      parsed.issued_at = value;
    } else if (name == "expires_at") {
      parsed.expires_at = value;
    } else if (name == "server_time") {
      parsed.server_time = value;
    } else if (name == "nonce") {
      parsed.nonce = value;
    } else if (name == "key_id") {
      parsed.key_id = value;
    }
    index = line_end + 1;
  }
  if (index != canonical.size()) {
    return false;
  }
  fields = std::move(parsed);
  return true;
}

}  // namespace kernauth
