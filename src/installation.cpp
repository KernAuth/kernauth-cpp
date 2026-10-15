#include "kernauth/installation.hpp"

#include <cstdlib>
#include <string>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#endif
#endif

namespace kernauth {
namespace {

std::string trim(std::string value) {
  const auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

bool acceptable(const std::string& value) {
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

std::string windows_sid() {
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
#else
  return "";
#endif
}

}  // namespace

std::string default_installation_id() {
  if (const char* env = std::getenv("KERN_INSTALLATION_ID")) {
    const std::string override_id = trim(env);
    if (acceptable(override_id)) {
      return override_id;
    }
  }
  const std::string sid = trim(windows_sid());
  return acceptable(sid) ? sid : "";
}

}  // namespace kernauth
