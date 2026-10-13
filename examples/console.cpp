#include "kernauth/cache.hpp"
#include "kernauth/client.hpp"
#include "kernauth/nonce.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <string>

namespace {

std::string trim(std::string value) {
  while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ' ||
                            value.back() == '\t')) {
    value.pop_back();
  }
  std::size_t start = 0;
  while (start < value.size() && (value[start] == ' ' || value[start] == '\t')) {
    ++start;
  }
  return value.substr(start);
}

bool is_hex_fingerprint(std::string_view value) {
  if (value.size() != 64) {
    return false;
  }
  for (const char character : value) {
    const bool digit = character >= '0' && character <= '9';
    const bool lower = character >= 'a' && character <= 'f';
    if (!digit && !lower) {
      return false;
    }
  }
  return true;
}

void print_failure(std::string_view code) {
  std::cout << "result=failure\n";
  std::cout << "code=" << code << "\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::string base_url = "https://api.kernauth.com";
  std::string public_app_id;
  std::string public_key;
  std::string key_id;
  std::string mode = "activate";
  std::string fingerprint;
  std::string installation_id = "install_kernauth_example";
  std::string label = "kernauth-example";
  std::string cache_path;

  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    auto need = [&](std::string& target) -> bool {
      if (index + 1 >= argc) {
        print_failure("invalid_arguments");
        return false;
      }
      target = argv[++index];
      return true;
    };
    if (argument == "--base-url") {
      if (!need(base_url)) {
        return 1;
      }
    } else if (argument == "--public-app-id") {
      if (!need(public_app_id)) {
        return 1;
      }
    } else if (argument == "--public-key") {
      if (!need(public_key)) return 1;
    } else if (argument == "--key-id") {
      if (!need(key_id)) return 1;
    } else if (argument == "--mode") {
      if (!need(mode)) return 1;
    } else if (argument == "--fingerprint") {
      if (!need(fingerprint)) {
        return 1;
      }
    } else if (argument == "--installation-id") {
      if (!need(installation_id)) {
        return 1;
      }
    } else if (argument == "--label") {
      if (!need(label)) {
        return 1;
      }
    } else if (argument == "--cache") {
      if (!need(cache_path)) {
        return 1;
      }
    } else {
      print_failure("invalid_arguments");
      return 1;
    }
  }

  if (public_app_id.empty()) {
    print_failure("missing_public_app_id");
    return 1;
  }
  if (public_key.empty() || key_id.empty() ||
      (mode != "activate" && mode != "validate" && mode != "deactivate")) {
    print_failure("missing_or_invalid_pinned_key_or_mode");
    return 1;
  }
  if (fingerprint.empty()) {
    fingerprint = kernauth::derive_device_fingerprint(1, installation_id);
  }
  if (!is_hex_fingerprint(fingerprint)) {
    print_failure("invalid_fingerprint");
    return 1;
  }

  std::string license_key;
  std::getline(std::cin, license_key);
  license_key = trim(std::move(license_key));
  if (license_key.empty()) {
    print_failure("missing_license_key");
    return 1;
  }

  kernauth::CurlTransport transport;
  kernauth::ClientOptions options;
  options.base_url = base_url;
  options.public_app_id = public_app_id;
  options.public_key_base64 = public_key;
  options.key_id = key_id;
  options.device_fingerprint = fingerprint;
  options.installation_id = installation_id;
  options.device_label = label;

  const kernauth::ClientResult activated = mode == "validate"
      ? kernauth::validate_license(transport, options, license_key)
      : mode == "deactivate" ? kernauth::deactivate(transport, options, license_key)
                             : kernauth::activate(transport, options, license_key);
  if (mode == "deactivate") {
    if (!activated.ok) {
      print_failure(activated.code.empty() ? "deactivate_failed" : activated.code);
      return 1;
    }
    std::cout << "result=deactivated\n";
    return 0;
  }
  if (!activated.active) {
    print_failure(activated.code.empty() ? "not_active" : activated.code);
    return 1;
  }

  if (!cache_path.empty()) {
    kernauth::StoredEntitlement stored;
    stored.canonical = kernauth::encode_entitlement(activated.entitlement);
    stored.signature_base64 = activated.signature_base64;
    stored.public_key_base64 = public_key;
    stored.stored_at = kernauth::utc_now_iso();
    std::ofstream cache(cache_path, std::ios::binary);
    if (cache) {
      cache << kernauth::serialize_cache(stored);
    }
  }

  std::cout << "result=active\n";
  std::cout << "status=" << activated.entitlement.status << "\n";
  std::cout << "application_id=" << activated.entitlement.application_id << "\n";
  std::cout << "key_id=" << activated.entitlement.key_id << "\n";
  return 0;
}
