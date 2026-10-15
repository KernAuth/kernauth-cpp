#include "kernauth.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <stdio.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

std::string trim(std::string value) {
  const auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

std::string environment_value(const char* name) {
  const char* value = std::getenv(name);
  return value == nullptr ? std::string() : trim(value);
}

bool stdin_is_terminal() {
#if defined(_WIN32)
  return _isatty(_fileno(stdin)) != 0;
#else
  return isatty(fileno(stdin)) != 0;
#endif
}

std::filesystem::path executable_directory() {
#if defined(_WIN32)
  wchar_t buffer[32768];
  const DWORD length = GetModuleFileNameW(nullptr, buffer, 32768);
  if (length == 0 || length >= 32768) {
    return std::filesystem::current_path();
  }
  return std::filesystem::path(buffer, buffer + length).parent_path();
#else
  char buffer[4096];
  const ssize_t length = ::readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
  if (length <= 0) {
    return std::filesystem::current_path();
  }
  buffer[length] = '\0';
  return std::filesystem::path(buffer).parent_path();
#endif
}

std::string random_hex() {
  std::random_device device;
  std::uniform_int_distribution<int> digits(0, 15);
  static constexpr char alphabet[] = "0123456789abcdef";
  std::string value(32, '0');
  for (char& cell : value) {
    cell = alphabet[static_cast<std::size_t>(digits(device))];
  }
  return value;
}

std::string license_key() {
  const std::string from_env = environment_value("KERN_LICENSE_KEY");
  if (!from_env.empty()) {
    return from_env;
  }
  if (stdin_is_terminal()) {
    std::cout << "Enter license: " << std::flush;
  }
  std::string line;
  std::getline(std::cin, line);
  return trim(line);
}

std::string installation_id() {
  const std::string from_env = environment_value("KERN_INSTALLATION_ID");
  if (!from_env.empty()) {
    return from_env;
  }
  const std::filesystem::path file = executable_directory() / "kernauth-install";
  {
    std::ifstream input(file);
    std::string saved;
    if (std::getline(input, saved)) {
      saved = trim(saved);
      if (!saved.empty()) {
        return saved;
      }
    }
  }
  const std::string created = random_hex();
  std::ofstream output(file);
  if (!output) {
    std::cerr << "Could not save the installation id\n";
    std::exit(1);
  }
  output << created << "\n";
  return created;
}

}  // namespace

int main() {
  kernauth::App app(
      "https://api.kernauth.com",
      "__PUBLIC_APP_ID__",
      "__KEY_ID__",
      "__PUBLIC_KEY__");
  app.set_installation(installation_id(), "desktop");

  const kernauth::ClientResult result = app.validate(license_key());
  if (!result.active) {
    std::cout << result.message << "\n";
    return 1;
  }
  std::cout << "Status: " << result.entitlement.status << "\n";
  std::cout << "Features: " << result.entitlement.features << "\n";
  std::cout << "License: " << result.entitlement.license_id << "\n";
  std::cout << "Check expires: " << result.entitlement.expires_at << "\n";
  return 0;
}
