#include "kernauth.hpp"

#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

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

void wipe(std::string& value) {
  volatile char* bytes = value.data();
  for (std::size_t index = 0; index < value.size(); ++index) {
    bytes[index] = '\0';
  }
  value.clear();
}

void wipe_bytes(unsigned char* data, std::size_t size) {
  volatile unsigned char* bytes = data;
  for (std::size_t index = 0; index < size; ++index) {
    bytes[index] = 0;
  }
}

}  // namespace

int main() {
  kernauth::App app(
      "https://api.kernauth.com",
      "__PUBLIC_APP_ID__",
      "__PUBLIC_KEY__");

  const std::string key = license_key();
  const kernauth::ClientResult session = app.initialize();
  if (!session.ok) {
    std::cout << session.message << "\n";
    return 1;
  }

  kernauth::ClientResult result = app.validate(key);
  if (!result.active) {
    std::cout << result.message << "\n";
    return 1;
  }

  kernauth::PayloadUnwrap payload = app.unwrap_payload();
  wipe(payload.payload_key);
  if (!payload.ok) {
    std::cout << payload.message << "\n";
    return 1;
  }

  const std::string file_name = env_or("KERN_FILE_NAME", "build");
  std::vector<kernauth::FileKey> keys = app.files();
  for (kernauth::FileKey& file : keys) {
    wipe_bytes(file.key.data(), file.key.size());
  }

  kernauth::DownloadResult downloaded = app.download(file_name);
  if (!downloaded.ok) {
    wipe_bytes(downloaded.bytes.data(), downloaded.bytes.size());
    std::cout << downloaded.message << "\n";
    return 1;
  }

  const std::string out_path = env_or("KERN_FILE_OUT", file_name.c_str());
  std::ofstream output(out_path, std::ios::binary);
  if (!output) {
    wipe_bytes(downloaded.bytes.data(), downloaded.bytes.size());
    std::cout << "Could not write the file\n";
    return 1;
  }
  if (!downloaded.bytes.empty()) {
    output.write(reinterpret_cast<const char*>(downloaded.bytes.data()),
                 static_cast<std::streamsize>(downloaded.bytes.size()));
  }
  output.close();
  wipe_bytes(downloaded.bytes.data(), downloaded.bytes.size());
  if (!output) {
    std::cout << "Could not write the file\n";
    return 1;
  }
  std::cout << "Wrote " << out_path << "\n";
  return 0;
}
