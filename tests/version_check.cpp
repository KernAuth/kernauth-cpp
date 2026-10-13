#include "kernauth/version.hpp"

#include <cstring>
#include <iostream>

int main() {
  const char* version = kernauth::sdkVersion();
  if (version == nullptr || std::strlen(version) == 0) {
    std::cerr << "sdk version is empty\n";
    return 1;
  }
  if (kernauth::kProtocolVersion != 1) {
    std::cerr << "unexpected protocol version\n";
    return 1;
  }
  std::cout << version << "\n";
  return 0;
}
