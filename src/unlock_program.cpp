#include "unlock.hpp"

#include <sodium.h>

#include <cstring>

void wipe_secret(std::string& value) {
  if (!value.empty()) {
    sodium_memzero(value.data(), value.size());
  }
  value.clear();
}

namespace {

constexpr std::size_t kNonceBytes = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr std::size_t kTagBytes = crypto_aead_xchacha20poly1305_ietf_ABYTES;

bool derive_key(std::string_view payload_key, unsigned char derived[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]) {
  return crypto_generichash(
             derived,
             crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
             reinterpret_cast<const unsigned char*>(payload_key.data()),
             payload_key.size(),
             nullptr,
             0) == 0;
}

}  // namespace

bool seal_bytes(std::string_view payload_key, const unsigned char* plain, std::size_t plain_len, std::string& sealed) {
  sealed.clear();
  if (payload_key.empty() || plain == nullptr || plain_len == 0 || sodium_init() < 0) {
    return false;
  }
  unsigned char derived[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  if (!derive_key(payload_key, derived)) {
    return false;
  }
  unsigned char nonce[kNonceBytes];
  randombytes_buf(nonce, sizeof nonce);
  std::string box(kNonceBytes + plain_len + kTagBytes, '\0');
  std::memcpy(box.data(), nonce, kNonceBytes);
  unsigned long long length = 0;
  const int sealed_ok = crypto_aead_xchacha20poly1305_ietf_encrypt(
      reinterpret_cast<unsigned char*>(box.data()) + kNonceBytes,
      &length,
      plain,
      plain_len,
      nullptr,
      0,
      nullptr,
      nonce,
      derived);
  sodium_memzero(derived, sizeof derived);
  sodium_memzero(nonce, sizeof nonce);
  if (sealed_ok != 0 || length != plain_len + kTagBytes) {
    sodium_memzero(box.data(), box.size());
    return false;
  }
  sealed = std::move(box);
  return true;
}

bool unlock_program(std::string_view payload_key, const unsigned char* sealed, std::size_t sealed_len, std::string& plain) {
  plain.clear();
  if (payload_key.empty() || sealed == nullptr || sealed_len <= kNonceBytes + kTagBytes || sodium_init() < 0) {
    return false;
  }
  unsigned char derived[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
  if (!derive_key(payload_key, derived)) {
    return false;
  }
  const unsigned char* nonce = sealed;
  const unsigned char* ciphertext = sealed + kNonceBytes;
  const unsigned long long ciphertext_length = sealed_len - kNonceBytes;
  std::string opened(static_cast<std::size_t>(ciphertext_length - kTagBytes), '\0');
  unsigned long long length = 0;
  const int opened_ok = crypto_aead_xchacha20poly1305_ietf_decrypt(
      reinterpret_cast<unsigned char*>(opened.data()),
      &length,
      nullptr,
      ciphertext,
      ciphertext_length,
      nullptr,
      0,
      nonce,
      derived);
  sodium_memzero(derived, sizeof derived);
  if (opened_ok != 0 || length == 0) {
    sodium_memzero(opened.data(), opened.size());
    return false;
  }
  opened.resize(static_cast<std::size_t>(length));
  plain = std::move(opened);
  return true;
}
