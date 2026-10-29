#pragma once

#include "kernauth/options.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kernauth {

class HttpTransport;

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

/**
 * Open one file_boxes entry. The box is nonce(12) || AES-256-GCM(session key, file key).
 * Writes 32 bytes to file_key_out. Returns false when AES-GCM or the box is unusable.
 */
bool unwrap_file_key(
    std::string_view box_base64,
    const std::array<unsigned char, 32>& session_key,
    std::array<unsigned char, 32>& file_key_out);

class App {
 public:
  App(
      std::string base_url,
      std::string public_app_id,
      std::string public_key_base64,
      std::string client_version = {});
  App(HttpTransport& transport, const ClientOptions& options);

  App(const App&) = delete;
  App& operator=(const App&) = delete;
  App(App&&) noexcept;
  App& operator=(App&&) noexcept;
  ~App();

  void set_installation(std::string installation_id, std::string label = "kernauth");
  void set_fingerprint(std::string fingerprint);

  /**
   * Create a session salt from HWID material, ask the API for the UTC hour bucket,
   * and derive the AES session secret used to unwrap payload_box on validate.
   */
  ClientResult initialize();
  ClientResult validate(std::string_view license_key);
  /** Check a key. Does not send a device and does not read the HWID. */
  ClientResult check(std::string_view license_key);
  ClientResult heartbeat(std::string_view license_key);

  /** Open payload_box from the last successful validate using the session secret. */
  PayloadUnwrap unwrap_payload() const;
  /** Open every file_boxes entry from the last successful validate. */
  std::vector<FileKey> files() const;
  /** Download one sealed file by name and return its plaintext bytes. */
  DownloadResult download(std::string_view name);

  bool session_ready() const;

  ClientResult response;

 private:
  struct Impl;
  const ClientResult* ensure_installation();
  ClientResult finish(ClientResult result);

  std::unique_ptr<Impl> impl_;
};

}  // namespace kernauth

#define hide(literal)                                                                          \
  ([]() -> std::string {                                                                       \
    constexpr static auto concealed =                                                          \
        ::kernauth::ConcealedString<sizeof(literal), ::kernauth::build_seed()>(literal);      \
    return concealed.reveal();                                                                 \
  }())
