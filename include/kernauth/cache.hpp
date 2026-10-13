#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <string_view>

namespace kernauth {

/** Default client-side offline grace. The server entitlement TTL stays short. */
inline constexpr std::chrono::hours kDefaultOfflineGrace{72};

struct StoredEntitlement {
  std::string canonical;
  std::string signature_base64;
  std::string public_key_base64;
  std::string stored_at;
};

struct CacheDecision {
  bool accepted = false;
  std::string reason;
};

/**
 * Accept a previously verified entitlement only inside the grace window,
 * before its own expiry, and only when the cached bytes still verify.
 * The stored record has no license key and no private signing key.
 */
CacheDecision evaluate_offline_cache(
    const StoredEntitlement& stored,
    std::string_view expected_application_id,
    std::string_view expected_key_id,
    std::string_view now_iso,
    std::chrono::seconds grace = std::chrono::duration_cast<std::chrono::seconds>(kDefaultOfflineGrace));

std::string serialize_cache(const StoredEntitlement& stored);
std::optional<StoredEntitlement> parse_cache(std::string_view text);

}  // namespace kernauth
