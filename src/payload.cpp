#include "payload.hpp"

#include "sealed_payload.hpp"

#include <sodium.h>

#include <cstddef>

bool open_sealed_payload(std::string_view payload_key, std::string& plain) {
  plain.clear();
  if (payload_key.empty() || sodium_init() < 0) {
    return false;
  }

  unsigned char derived[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  if (crypto_generichash(
          derived,
          sizeof derived,
          reinterpret_cast<const unsigned char*>(payload_key.data()),
          payload_key.size(),
          nullptr,
          0) != 0) {
    return false;
  }

  static_assert(sizeof kSealedNonce == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  static_assert(sizeof kSealedPayload > crypto_aead_xchacha20poly1305_ietf_ABYTES);
  std::string opened(sizeof kSealedPayload - crypto_aead_xchacha20poly1305_ietf_ABYTES, '\0');
  unsigned long long length = 0;
  const int opened_ok = crypto_aead_xchacha20poly1305_ietf_decrypt(
      reinterpret_cast<unsigned char*>(opened.data()),
      &length,
      nullptr,
      kSealedPayload,
      sizeof kSealedPayload,
      nullptr,
      0,
      kSealedNonce,
      derived);
  sodium_memzero(derived, sizeof derived);
  if (opened_ok != 0) {
    sodium_memzero(opened.data(), opened.size());
    return false;
  }
  opened.resize(static_cast<std::size_t>(length));
  plain = std::move(opened);
  return true;
}

void wipe_secret(std::string& value) {
  if (!value.empty()) {
    sodium_memzero(value.data(), value.size());
  }
  value.clear();
}
