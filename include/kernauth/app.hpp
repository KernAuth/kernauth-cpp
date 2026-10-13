#pragma once

#include "kernauth/client.hpp"
#include "kernauth/nonce.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace kernauth {

// One application. Construct it with the values from Developers, then call
// activate, validate, or deactivate. The last call is also stored in response.
class App {
 public:
  App(std::string base_url, std::string public_app_id, std::string key_id, std::string public_key_base64)
      : owned_(std::make_unique<CurlTransport>()), transport_(owned_.get()) {
    options_.base_url = std::move(base_url);
    options_.public_app_id = std::move(public_app_id);
    options_.key_id = std::move(key_id);
    options_.public_key_base64 = std::move(public_key_base64);
  }

  App(HttpTransport& transport, ClientOptions options)
      : transport_(&transport), options_(std::move(options)) {}

  App(const App&) = delete;
  App& operator=(const App&) = delete;
  App(App&&) noexcept = default;
  App& operator=(App&&) noexcept = default;

  void set_installation(std::string installation_id, std::string label = "kernauth") {
    options_.installation_id = std::move(installation_id);
    options_.device_label = std::move(label);
    if (options_.device_fingerprint.empty()) {
      options_.device_fingerprint =
          derive_device_fingerprint(options_.fingerprint_version, options_.installation_id);
    }
  }

  void set_fingerprint(std::string fingerprint) {
    options_.device_fingerprint = std::move(fingerprint);
  }

  ClientResult activate(std::string_view license_key) {
    return finish(kernauth::activate(*transport_, options_, license_key));
  }

  ClientResult validate(std::string_view license_key) {
    return finish(validate_license(*transport_, options_, license_key));
  }

  ClientResult deactivate(std::string_view license_key) {
    return finish(kernauth::deactivate(*transport_, options_, license_key));
  }

  ClientResult response;

 private:
  ClientResult finish(ClientResult result) {
    if (result.ok && result.message.empty()) {
      result.message = result.code == "deactivated" ? "Device deactivated" : "License is active";
    }
    response = std::move(result);
    return response;
  }

  std::unique_ptr<CurlTransport> owned_;
  HttpTransport* transport_ = nullptr;
  ClientOptions options_;
};

}  // namespace kernauth
