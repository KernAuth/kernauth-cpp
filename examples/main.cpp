#include "kernauth.hpp"

#include <iostream>
#include <string>

int main() {
  kernauth::App app(
      hide("https://api.kernauth.com"),
      hide("__PUBLIC_APP_ID__"),
      hide("__KEY_ID__"),
      hide("__PUBLIC_KEY__"));
  app.set_installation(hide("install_your_device"), "desktop");

  std::string license_key;
  std::getline(std::cin, license_key);
  if (!app.activate(license_key).active) {
    std::cout << app.response.message << "\n";
    return 1;
  }
  if (!app.validate(license_key).active) {
    std::cout << app.response.message << "\n";
    return 1;
  }
  if (!app.deactivate(license_key).ok) {
    std::cout << app.response.message << "\n";
    return 1;
  }
  std::cout << app.response.message << "\n";
  return 0;
}
