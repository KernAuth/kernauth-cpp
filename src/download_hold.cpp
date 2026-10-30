#include "download_hold.hpp"

#include <cstddef>
#include <string>

namespace kernauth {
namespace {

void wipe_bytes(unsigned char* data, std::size_t size) {
  if (data == nullptr || size == 0) {
    return;
  }
  volatile unsigned char* bytes = data;
  for (std::size_t index = 0; index < size; ++index) {
    bytes[index] = 0;
  }
}

char hex_digit(unsigned value) {
  return static_cast<char>(value < 10 ? '0' + value : 'a' + (value - 10));
}

}  // namespace

std::string delivery_line(std::string_view payload, const std::vector<unsigned char>& bytes) {
  std::string prefix;
  const std::size_t count = bytes.size() < 8 ? bytes.size() : 8;
  prefix.reserve(count * 2);
  for (std::size_t index = 0; index < count; ++index) {
    const unsigned char byte = bytes[index];
    prefix.push_back(hex_digit(byte >> 4));
    prefix.push_back(hex_digit(byte & 0x0f));
  }
  return "payload:" + std::string(payload) + " bytes:" + std::to_string(bytes.size()) + ":" + prefix;
}

void wipe_secret(std::string& value) {
  volatile char* data = value.data();
  for (std::size_t index = 0; index < value.size(); ++index) {
    data[index] = '\0';
  }
  value.clear();
}

int release_download(bool active, DownloadResult& file, const std::filesystem::path& output_path) {
  (void)output_path;
  if (!active || !file.ok) {
    return 1;
  }
  wipe_bytes(file.bytes.data(), file.bytes.size());
  return 0;
}

}  // namespace kernauth
