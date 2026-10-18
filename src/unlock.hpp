#pragma once

#include <string>
#include <string_view>

// Opens the one-time lock in the signed ticket and wipes those fields.
// Returns the dashboard payload key for this login only.
std::string unlock_payload_key(std::string& features_json);

// Seals plain bytes. Output is a 24-byte nonce followed by ciphertext and tag.
bool seal_bytes(std::string_view payload_key, const unsigned char* plain, std::size_t plain_len, std::string& sealed);

// Opens a sealed loader. `sealed` is the nonce followed by ciphertext and tag.
bool unlock_program(std::string_view payload_key, const unsigned char* sealed, std::size_t sealed_len, std::string& plain);

void wipe_secret(std::string& value);
