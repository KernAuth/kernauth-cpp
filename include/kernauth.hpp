#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kernauth {

class HttpTransport;

constexpr int kProtocolVersion = 1;

struct EntitlementFields {
  int protocol_version = kProtocolVersion;
  std::string entitlement_id;
  std::string application_id;
  std::string license_id;
  std::string status;
  std::string features;
  std::string device_id;
  std::string issued_at;
  std::string expires_at;
  std::string server_time;
  std::string nonce;
  std::string key_id;
};

struct ClientOptions {
  std::string base_url;
  std::string public_app_id;
  std::string public_key_base64;
  std::string key_id;
  std::string client_version = "0.4.0";
  int fingerprint_version = 1;
  std::string device_fingerprint;
  std::string installation_id;
  std::string device_label;
  /** From App.initialize() — required when the application has a payload key. */
  std::string session_salt;
  std::string time_bucket;
  /** SHA-256 of the program. Sent on validate only when the application lists hashes. */
  std::string program_digest;
  std::function<std::string()> nonce_generator;
  std::function<std::string()> now_iso;
};

struct ClientResult {
  bool ok = false;
  bool active = false;
  int http_status = 0;
  std::string code;
  std::string message;
  std::string request_id;
  EntitlementFields entitlement;
  std::string signature_base64;
};

struct PayloadUnwrap {
  bool ok = false;
  std::string payload_key;
  std::string message;
};

struct FileKey {
  std::string name;
  std::array<unsigned char, 32> key{};
};

struct DownloadResult {
  bool ok = false;
  std::string message;
  std::vector<unsigned char> bytes;
};

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
  void set_program_digest(std::string digest);

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
  /**
   * Read one named string from the last verified validate features.
   * A missing name, a non-string, or an inactive result returns empty.
   */
  std::string string(std::string_view name) const;
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
