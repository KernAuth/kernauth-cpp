#include "download_hold.hpp"

#include <cstddef>

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

}  // namespace

int release_download(bool active, DownloadResult& file, const std::filesystem::path& output_path) {
  (void)output_path;
  if (!active || !file.ok) {
    return 1;
  }
  wipe_bytes(file.bytes.data(), file.bytes.size());
  return 0;
}

}  // namespace kernauth
