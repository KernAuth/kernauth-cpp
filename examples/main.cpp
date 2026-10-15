#include "kernauth.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <sddl.h>
#include <stdio.h>
#include <windows.h>
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#endif
#else
#include <unistd.h>
#if defined(__APPLE__)
#include <stdio.h>
#endif
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

bool acceptable_hwid(const std::string& value) {
  if (value.size() < 8 || value.size() > 64) {
    return false;
  }
  for (const unsigned char cell : value) {
    const bool ok = (cell >= 'A' && cell <= 'Z') || (cell >= 'a' && cell <= 'z') ||
                    (cell >= '0' && cell <= '9') || cell == '_' || cell == '-';
    if (!ok) {
      return false;
    }
  }
  return true;
}

std::string machine_hwid() {
#if defined(_WIN32)
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == 0) {
    return "";
  }
  DWORD length = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &length);
  std::string buffer(length, '\0');
  if (GetTokenInformation(token, TokenUser, buffer.data(), length, &length) == 0) {
    CloseHandle(token);
    return "";
  }
  CloseHandle(token);
  const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  char* sid = nullptr;
  if (ConvertSidToStringSidA(user->User.Sid, &sid) == 0 || sid == nullptr) {
    return "";
  }
  const std::string value(sid);
  LocalFree(sid);
  return value;
#elif defined(__APPLE__)
  FILE* pipe = popen("ioreg -rd1 -c IOPlatformExpertDevice", "r");
  if (pipe == nullptr) {
    return "";
  }
  std::string output;
  char chunk[512];
  while (fgets(chunk, sizeof(chunk), pipe) != nullptr) {
    output += chunk;
  }
  pclose(pipe);
  const std::string marker = "\"IOPlatformUUID\" = \"";
  const auto start = output.find(marker);
  if (start == std::string::npos) {
    return "";
  }
  const auto value_start = start + marker.size();
  const auto end = output.find('"', value_start);
  if (end == std::string::npos) {
    return "";
  }
  return output.substr(value_start, end - value_start);
#else
  std::ifstream input("/etc/machine-id");
  std::string value;
  std::getline(input, value);
  return value;
#endif
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
  const std::string hwid = trim(machine_hwid());
  if (acceptable_hwid(hwid)) {
    return hwid;
  }
  std::cerr << "Could not read the HWID\n";
  std::exit(1);
}

}  // namespace

int main() {
  kernauth::App app(
      "https://api.kernauth.com",
      "__PUBLIC_APP_ID__",
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
