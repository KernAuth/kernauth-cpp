#include "kernauth.hpp"

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

}  // namespace

int main() {
  kernauth::App app(
      "https://api.kernauth.com",
      "__PUBLIC_APP_ID__",
      "__PUBLIC_KEY__");

  const std::string key = license_key();
  const kernauth::ClientResult result = app.validate(key);
  if (!result.active) {
    std::cout << result.message << "\n";
    return 1;
  }
  std::cout << "Status: " << result.entitlement.status << "\n";
  std::cout << "Features: " << result.entitlement.features << "\n";
  std::cout << "License: " << result.entitlement.license_id << "\n";
  std::cout << "Check expires: " << result.entitlement.expires_at << "\n";
  for (;;) {
    std::this_thread::sleep_for(std::chrono::seconds(60));
    const kernauth::ClientResult beat = app.heartbeat(key);
    if (!beat.ok) {
      std::cout << beat.message << "\n";
      return 1;
    }
  }
}
