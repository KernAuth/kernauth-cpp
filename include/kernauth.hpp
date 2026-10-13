#pragma once

#include "kernauth/client.hpp"
#include "kernauth/nonce.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace kernauth {

constexpr std::uint64_t mix64(std::uint64_t value) {
  value += 0x9E3779B97F4A7C15ull;
  value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
  value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
  return value ^ (value >> 31);
}

constexpr std::uint8_t stream_byte(std::uint64_t seed, std::size_t index) {
  const std::uint64_t mixed = mix64(seed + static_cast<std::uint64_t>(index) * 0xD1B54A32D192ED03ull);
  return static_cast<std::uint8_t>(mixed >> ((index & 7u) * 8u));
}

template <std::size_t Size, std::uint64_t Seed>
class ConcealedString {
 public:
  constexpr explicit ConcealedString(const char (&plain)[Size]) : bytes_{} {
    for (std::size_t index = 0; index < Size; ++index) {
      bytes_[index] = static_cast<char>(
          static_cast<unsigned char>(plain[index]) ^ stream_byte(Seed, index));
    }
  }

  std::string reveal() const {
    std::string out(Size == 0 ? 0 : Size - 1, '\0');
    for (std::size_t index = 0; index + 1 < Size; ++index) {
      out[index] = static_cast<char>(
          static_cast<unsigned char>(bytes_[index]) ^ stream_byte(Seed, index));
    }
    return out;
  }

  constexpr unsigned char stored(std::size_t index) const {
    return static_cast<unsigned char>(bytes_[index]);
  }

 private:
  char bytes_[Size];
};

constexpr std::uint64_t build_seed() {
  constexpr char stamp[] = __DATE__ " " __TIME__;
  std::uint64_t hash = 0x6B65726E61757468ull;
  for (const char character : stamp) {
    hash = mix64(hash ^ static_cast<unsigned char>(character));
  }
  return hash == 0 ? 0xA5A5A5A5A5A5A5A5ull : hash;
}

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

  ClientResult validate(std::string_view license_key) {
    return finish(validate_license(*transport_, options_, license_key));
  }

  ClientResult response;

 private:
  ClientResult finish(ClientResult result) {
    if (result.ok && result.message.empty()) {
      result.message = "License is active";
    }
    response = std::move(result);
    return response;
  }

  std::unique_ptr<CurlTransport> owned_;
  HttpTransport* transport_ = nullptr;
  ClientOptions options_;
};

}  // namespace kernauth

#define hide(literal)                                                                          \
  ([]() -> std::string {                                                                       \
    constexpr static auto concealed =                                                          \
        ::kernauth::ConcealedString<sizeof(literal), ::kernauth::build_seed()>(literal);      \
    return concealed.reveal();                                                                 \
  }())
