#pragma once

#include <cstdlib>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
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
namespace detail {

inline std::string trim_copy(std::string value) {
  const auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

inline bool acceptable_installation(const std::string& value) {
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

inline std::string windows_user_sid() {
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

}  // namespace detail

/** Windows user SID, or KERN_INSTALLATION_ID when that override is set. Empty when neither is usable. */
inline std::string default_installation_id() {
  if (const char* env = std::getenv("KERN_INSTALLATION_ID")) {
    const std::string override_id = detail::trim_copy(env);
    if (detail::acceptable_installation(override_id)) {
      return override_id;
    }
  }
  const std::string sid = detail::trim_copy(detail::windows_user_sid());
  return detail::acceptable_installation(sid) ? sid : "";
}

}  // namespace kernauth
