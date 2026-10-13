#pragma once

// Compile-time concealment for string literals. The static object stores a
// keystream XOR, so a plain strings dump does not show the literal.
// A compiler may still keep its own copy. This does not stop a patched binary
// from skipping the license check.

#include <cstddef>
#include <cstdint>
#include <string>

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

}  // namespace kernauth

#define KERNAUTH_CONCEAL(literal)                                                              \
  ([]() {                                                                                      \
    constexpr static auto concealed =                                                          \
        ::kernauth::ConcealedString<sizeof(literal), ::kernauth::build_seed()>(literal);      \
    return concealed;                                                                          \
  }())
