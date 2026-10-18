#include "kernauth.hpp"
#include "payload.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

namespace {

std::string trim(std::string value) {
  const auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

std::string license_key() {
  if (const char* env = std::getenv("KERN_LICENSE_KEY")) {
    const std::string value = trim(env);
    if (!value.empty()) {
      return value;
    }
  }
  std::cout << "Enter license: " << std::flush;
  std::string line;
  std::getline(std::cin, line);
  return trim(line);
}

std::string read_payload_key(std::string& features_json) {
  const auto features = nlohmann::json::parse(features_json, nullptr, false);
  std::string wrap_key;
  std::string payload_box;
  if (features.is_object()) {
    if (features.contains("wrap_key") && features["wrap_key"].is_string()) {
      wrap_key = features["wrap_key"].get<std::string>();
    }
    if (features.contains("payload_box") && features["payload_box"].is_string()) {
      payload_box = features["payload_box"].get<std::string>();
    }
  }
  wipe_secret(features_json);
  std::string payload_key;
  const bool opened = unwrap_payload_key(wrap_key, payload_box, payload_key);
  wipe_secret(wrap_key);
  wipe_secret(payload_box);
  if (!opened) {
    wipe_secret(payload_key);
  }
  return payload_key;
}

}  // namespace

int main() {
  kernauth::App app(
      "https://api.kernauth.com",
      "__PUBLIC_APP_ID__",
      "__PUBLIC_KEY__");

  const std::string key = license_key();
  kernauth::ClientResult result = app.validate(key);
  if (!result.active) {
    std::cout << result.message << "\n";
    return 1;
  }

  std::string payload_key = read_payload_key(result.entitlement.features);
  std::string plain;
  const bool opened = open_sealed_payload(payload_key, plain);
  wipe_secret(payload_key);
  if (!opened) {
    std::cout << "The payload key could not open this build.\n";
    return 1;
  }

  std::cout << plain << "\n";
  std::cout << "Status: " << result.entitlement.status << "\n";
  std::cout << "License: " << result.entitlement.license_id << "\n";
  std::cout << "Check expires: " << result.entitlement.expires_at << "\n";
  for (;;) {
    std::this_thread::sleep_for(std::chrono::seconds(60));
    const kernauth::ClientResult beat = app.heartbeat(key);
    if (!beat.ok) {
      wipe_secret(plain);
      std::cout << beat.message << "\n";
      return 1;
    }
  }
}
