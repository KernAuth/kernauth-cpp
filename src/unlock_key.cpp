#include "unlock.hpp"

#include <nlohmann/json.hpp>
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

bool open_box(std::string_view wrap_key, std::string_view payload_box, std::string& payload_key) {
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

}  // namespace

std::string unlock_payload_key(std::string& features_json) {
  const auto features = nlohmann::json::parse(features_json, nullptr, false);
  std::string wrap_key;
  std::string payload_box;
  if (features.is_object()) {
    if (features.contains("wrap_key") && features["wrap_key"].is_string()) {
      wrap_key = features["wrap_key"].get<std::string>();
    }
    if (features.contains("payload_box") && features["payload_box"].is_string()) {
      payload_box = features["payload_box"].get<std::string>();
    }
  }
  wipe_secret(features_json);
  std::string payload_key;
  const bool opened = open_box(wrap_key, payload_box, payload_key);
  wipe_secret(wrap_key);
  wipe_secret(payload_box);
  if (!opened) {
    wipe_secret(payload_key);
  }
  return payload_key;
}
