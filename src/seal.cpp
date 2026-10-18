#include "unlock.hpp"

#include <fstream>
#include <iostream>
#include <string>

namespace {

bool acceptable_key(std::string_view key) {
  if (key.size() < 8 || key.size() > 128) {
    return false;
  }
  for (const unsigned char c : key) {
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' ||
                    c == '/' || c == '=' || c == '_' || c == '-';
    if (!ok) {
      return false;
    }
  }
  return true;
}

bool read_file(const char* path, std::string& bytes) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return false;
  }
  input.seekg(0, std::ios::end);
  const std::streamoff end = input.tellg();
  if (end < 0) {
    return false;
  }
  input.seekg(0, std::ios::beg);
  bytes.assign(static_cast<std::size_t>(end), '\0');
  if (end == 0) {
    return true;
  }
  input.read(bytes.data(), end);
  return static_cast<bool>(input);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "usage: seal <payload-key> <loader-file> <loader.sealed>\n";
    return 1;
  }
  if (!acceptable_key(argv[1])) {
    std::cerr << "The payload key must be 8 to 128 characters from A-Za-z0-9+/=_-.\n";
    return 1;
  }
  std::string loader;
  if (!read_file(argv[2], loader)) {
    std::cerr << "Could not open the loader file.\n";
    return 1;
  }
  if (loader.empty()) {
    std::cerr << "The loader file is empty.\n";
    return 1;
  }
  std::string sealed;
  const bool sealed_ok = seal_bytes(
      argv[1],
      reinterpret_cast<const unsigned char*>(loader.data()),
      loader.size(),
      sealed);
  wipe_secret(loader);
  if (!sealed_ok) {
    std::cerr << "Could not seal the loader.\n";
    return 1;
  }
  std::ofstream output(argv[3], std::ios::binary | std::ios::trunc);
  if (!output) {
    std::cerr << "Could not write the sealed file.\n";
    return 1;
  }
  output.write(sealed.data(), static_cast<std::streamsize>(sealed.size()));
  if (!output) {
    std::cerr << "Could not write the sealed file.\n";
    return 1;
  }
  return 0;
}
