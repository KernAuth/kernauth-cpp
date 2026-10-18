#include "payload.hpp"

#include "sealed_payload.hpp"

#include <sodium.h>

#include <cstddef>
#include <vector>

namespace {

bool decode_base64(std::string_view text, std::size_t max_bytes, std::vector<unsigned char>& out) {
  out.assign(max_bytes, 0);
  std::size_t length = 0;
  if (sodium_base642bin(
          out.data(),
          out.size(),
          text.data(),
          text.size(),
          nullptr,
          &length,
          nullptr,
          sodium_base64_VARIANT_ORIGINAL) != 0) {
    out.clear();
    return false;
  }
  out.resize(length);
  return true;
}

}  // namespace

bool unwrap_payload_key(std::string_view wrap_key, std::string_view payload_box, std::string& payload_key) {
  payload_key.clear();
  if (wrap_key.empty() || payload_box.empty() || sodium_init() < 0 || crypto_aead_aes256gcm_is_available() == 0) {
    return false;
  }
  std::vector<unsigned char> key_bytes;
  std::vector<unsigned char> box;
  if (!decode_base64(wrap_key, 64, key_bytes) || key_bytes.size() != crypto_aead_aes256gcm_KEYBYTES) {
    return false;
  }
  if (!decode_base64(payload_box, 512, box) ||
      box.size() <= crypto_aead_aes256gcm_NPUBBYTES + crypto_aead_aes256gcm_ABYTES) {
    sodium_memzero(key_bytes.data(), key_bytes.size());
    return false;
  }
  const unsigned char* nonce = box.data();
  const unsigned char* ciphertext = box.data() + crypto_aead_aes256gcm_NPUBBYTES;
  const unsigned long long ciphertext_length = box.size() - crypto_aead_aes256gcm_NPUBBYTES;
  std::string opened(static_cast<std::size_t>(ciphertext_length - crypto_aead_aes256gcm_ABYTES), '\0');
  unsigned long long length = 0;
  const int opened_ok = crypto_aead_aes256gcm_decrypt(
      reinterpret_cast<unsigned char*>(opened.data()),
      &length,
      nullptr,
      ciphertext,
      ciphertext_length,
      nullptr,
      0,
      nonce,
      key_bytes.data());
  sodium_memzero(key_bytes.data(), key_bytes.size());
  if (opened_ok != 0) {
    sodium_memzero(opened.data(), opened.size());
    return false;
  }
  opened.resize(static_cast<std::size_t>(length));
  payload_key = std::move(opened);
  return !payload_key.empty();
}

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
