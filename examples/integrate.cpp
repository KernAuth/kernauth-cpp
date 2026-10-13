#include "kernauth/app.hpp"
#include "kernauth/conceal.hpp"

#include <iostream>
#include <string>

namespace {

std::string trim(std::string value) {
  while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ' ||
                            value.back() == '\t')) {
    value.pop_back();
  }
  std::size_t start = 0;
  while (start < value.size() && (value[start] == ' ' || value[start] == '\t')) {
    ++start;
  }
  return value.substr(start);
}

}  // namespace

int main() {
  // Paste the public app ID, key ID, and public key from Developers.
  // KERNAUTH_CONCEAL keeps those literals out of a plain strings dump.
  // It does not stop someone from patching out the check.
  const std::string base_url = KERNAUTH_CONCEAL("https://api.kernauth.com").reveal();
  const std::string app_id = KERNAUTH_CONCEAL("__PUBLIC_APP_ID__").reveal();
  const std::string key_id = KERNAUTH_CONCEAL("__KEY_ID__").reveal();
  const std::string public_key = KERNAUTH_CONCEAL("__PUBLIC_KEY__").reveal();

  kernauth::App app(base_url, app_id, key_id, public_key);
  // Persist one installation ID per device and reuse it.
  const std::string installation_id = KERNAUTH_CONCEAL("install_your_device").reveal();
  app.set_installation(installation_id, "desktop");

  std::string license_key;
  std::getline(std::cin, license_key);
  license_key = trim(std::move(license_key));
  if (license_key.empty()) {
    std::cout << "missing license key\n";
    return 1;
  }

  app.activate(license_key);
  if (!app.response.ok || !app.response.active) {
    std::cout << app.response.message << "\n";
    return 1;
  }

  app.validate(license_key);
  if (!app.response.active) {
    std::cout << app.response.message << "\n";
    return 1;
  }

  app.deactivate(license_key);
  if (!app.response.ok) {
    std::cout << app.response.message << "\n";
    return 1;
  }
  std::cout << app.response.message << "\n";
  return 0;
}
