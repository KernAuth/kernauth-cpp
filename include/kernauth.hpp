#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
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

constexpr std::uint32_t seal_rotr(std::uint32_t value, std::uint32_t bits) {
  return (value >> bits) | (value << (32 - bits));
}

/** SHA-256 of `data`. A zero length does not read `data`. */
constexpr std::array<unsigned char, 32> sha256(const unsigned char* data, std::size_t length) {
  constexpr std::uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  std::uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  const std::size_t bits_hi = static_cast<std::uint32_t>((length / 0x20000000u));
  const std::uint32_t bits_lo = static_cast<std::uint32_t>(length << 3);
  const std::size_t padded = ((length + 9 + 63) / 64) * 64;
  for (std::size_t offset = 0; offset < padded; offset += 64) {
    std::uint32_t word[64] = {};
    for (std::size_t i = 0; i < 16; ++i) {
      std::uint32_t value = 0;
      for (std::size_t byte = 0; byte < 4; ++byte) {
        const std::size_t index = offset + i * 4 + byte;
        unsigned char piece = 0;
        if (index < length) {
          piece = data[index];
        } else if (index == length) {
          piece = 0x80;
        } else if (offset + 64 - index <= 8 && index >= padded - 8) {
          const std::size_t from_end = padded - 1 - index;
          const std::uint64_t bits = (static_cast<std::uint64_t>(bits_hi) << 32) | bits_lo;
          piece = static_cast<unsigned char>((bits >> (from_end * 8)) & 0xff);
        }
        value = (value << 8) | piece;
      }
      word[i] = value;
    }
    for (std::size_t i = 16; i < 64; ++i) {
      const std::uint32_t s0 = seal_rotr(word[i - 15], 7) ^ seal_rotr(word[i - 15], 18) ^ (word[i - 15] >> 3);
      const std::uint32_t s1 = seal_rotr(word[i - 2], 17) ^ seal_rotr(word[i - 2], 19) ^ (word[i - 2] >> 10);
      word[i] = word[i - 16] + s0 + word[i - 7] + s1;
    }
    std::uint32_t a = state[0];
    std::uint32_t b = state[1];
    std::uint32_t c = state[2];
    std::uint32_t d = state[3];
    std::uint32_t e = state[4];
    std::uint32_t f = state[5];
    std::uint32_t g = state[6];
    std::uint32_t h = state[7];
    for (std::size_t i = 0; i < 64; ++i) {
      const std::uint32_t s1 = seal_rotr(e, 6) ^ seal_rotr(e, 11) ^ seal_rotr(e, 25);
      const std::uint32_t choice = (e & f) ^ ((~e) & g);
      const std::uint32_t temp1 = h + s1 + choice + k[i] + word[i];
      const std::uint32_t s0 = seal_rotr(a, 2) ^ seal_rotr(a, 13) ^ seal_rotr(a, 22);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temp2 = s0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
  }
  std::array<unsigned char, 32> out{};
  for (std::size_t i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<unsigned char>((state[i] >> 24) & 0xff);
    out[i * 4 + 1] = static_cast<unsigned char>((state[i] >> 16) & 0xff);
    out[i * 4 + 2] = static_cast<unsigned char>((state[i] >> 8) & 0xff);
    out[i * 4 + 3] = static_cast<unsigned char>(state[i] & 0xff);
  }
  return out;
}

/** One private block stored in the `.kaseal` section. The file name is not part of the block. */
template <std::size_t N>
struct SealBlock {
  char magic[8];
  std::uint32_t size;
  unsigned char hash[32];
  unsigned char bytes[N];
};

template <std::size_t N>
constexpr SealBlock<N> make_seal_block(const unsigned char (&input)[N]) {
  SealBlock<N> block{};
  block.magic[0] = 'K';
  block.magic[1] = 'A';
  block.magic[2] = 'S';
  block.magic[3] = 'E';
  block.magic[4] = 'A';
  block.magic[5] = 'L';
  block.magic[6] = '1';
  block.size = static_cast<std::uint32_t>(N);
  const std::array<unsigned char, 32> digest = sha256(input, N);
  for (std::size_t i = 0; i < 32; ++i) {
    block.hash[i] = digest[i];
  }
  for (std::size_t i = 0; i < N; ++i) {
    block.bytes[i] = input[i];
  }
  return block;
}

static_assert(std::is_standard_layout_v<SealBlock<1>>);
static_assert(std::is_trivial_v<SealBlock<1>>);
static_assert(offsetof(SealBlock<1>, magic) == 0);
static_assert(offsetof(SealBlock<1>, size) == 8);
static_assert(offsetof(SealBlock<1>, hash) == 12);
static_assert(offsetof(SealBlock<1>, bytes) == 44);

namespace detail {

template <std::size_t N>
struct SealBytes {
  unsigned char data[N]{};
};

template <typename T, std::size_t N>
constexpr SealBytes<N> seal_capture(const T (&input)[N]) {
  static_assert(std::is_convertible_v<T, unsigned char>);
  SealBytes<N> out{};
  for (std::size_t i = 0; i < N; ++i) {
    out.data[i] = static_cast<unsigned char>(input[i]);
  }
  return out;
}

template <typename T, std::size_t N>
constexpr SealBytes<N> seal_capture(T (&&input)[N]) {
  static_assert(std::is_convertible_v<T, unsigned char>);
  SealBytes<N> out{};
  for (std::size_t i = 0; i < N; ++i) {
    out.data[i] = static_cast<unsigned char>(input[i]);
  }
  return out;
}

template <std::size_t N>
constexpr SealBlock<N> place_seal(const SealBytes<N>& captured) {
  return make_seal_block(captured.data);
}

}  // namespace detail

}  // namespace kernauth

#define hide(literal)                                                                          \
  ([]() -> std::string {                                                                       \
    constexpr static auto concealed =                                                          \
        ::kernauth::ConcealedString<sizeof(literal), ::kernauth::build_seed()>(literal);      \
    return concealed.reveal();                                                                 \
  }())

// The running program must ignore the .kaseal section and use download.
// The bytes argument is a brace initializer or a constexpr array. One translation unit owns the block.
#if defined(_MSC_VER)
#pragma section(".kaseal", read)
#define KERNAUTH_SEAL(name, ...)                                                                   \
  __declspec(allocate(".kaseal")) static constexpr auto name =                                     \
      ::kernauth::detail::place_seal(::kernauth::detail::seal_capture(__VA_ARGS__))
#else
#define KERNAUTH_SEAL(name, ...)                                                                   \
  static_assert(false, "KERNAUTH_SEAL requires MSVC so the private bytes land in .kaseal")
#endif
