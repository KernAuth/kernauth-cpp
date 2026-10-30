#include "kernauth.hpp"
#include "download_hold.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

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

std::string env_or(const char* name, const char* fallback) {
  if (const char* env = std::getenv(name)) {
    const std::string value = trim(env);
    if (!value.empty()) {
      return value;
    }
  }
  return fallback;
}

}  // namespace

int main() {
  kernauth::App app(
      "https://api.kernauth.com",
      hide("__PUBLIC_APP_ID__"),
      hide("__PUBLIC_KEY__"));

  const std::string key = license_key();
  const kernauth::ClientResult session = app.initialize();
  if (!session.ok) {
    std::cout << session.message << "\n";
    return 1;
  }

  const kernauth::ClientResult result = app.validate(key);
  const std::string file_name = env_or("KERN_FILE_NAME", "build");
  const std::filesystem::path output{file_name};
  if (!result.active) {
    kernauth::DownloadResult unused;
    kernauth::release_download(false, unused, output);
    std::cout << result.message << "\n";
    return 1;
  }

  kernauth::DownloadResult file = app.download(file_name);
  if (kernauth::release_download(file.ok, file, output) != 0) {
    std::cout << file.message << "\n";
    return 1;
  }
  std::cout << "Held " << file_name << "\n";
  return 0;
}
