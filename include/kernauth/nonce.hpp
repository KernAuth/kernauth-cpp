#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace kernauth {

/** 32 cryptographic random bytes, hex-encoded. Matches the client nonce pattern. */
std::string random_nonce();

/** SHA-256 hex of a versioned installation marker. This is not a hardware serial. */
std::string derive_device_fingerprint(int fingerprint_version, std::string_view installation_id);

std::string format_iso_utc(std::chrono::system_clock::time_point time);
std::string utc_now_iso();
bool parse_iso_utc(std::string_view text, std::chrono::system_clock::time_point& time);

}  // namespace kernauth
