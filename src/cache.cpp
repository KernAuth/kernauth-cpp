#include "kernauth/cache.hpp"

#include "kernauth/canonical.hpp"
#include "kernauth/nonce.hpp"
#include "kernauth/verify.hpp"

#include <sstream>

namespace kernauth {
namespace {

constexpr std::string_view kCanonicalPrefix = "canonical:";

}  // namespace

CacheDecision evaluate_offline_cache(
    const StoredEntitlement& stored,
    std::string_view expected_application_id,
    std::string_view expected_key_id,
    std::string_view now_iso,
    std::chrono::seconds grace) {
  CacheDecision decision;
  std::chrono::system_clock::time_point stored_at;
  std::chrono::system_clock::time_point now;
  if (!parse_iso_utc(stored.stored_at, stored_at) || !parse_iso_utc(now_iso, now)) {
    decision.reason = "malformed_time";
    return decision;
  }
  const auto age = std::chrono::duration_cast<std::chrono::seconds>(now - stored_at);
  if (age < std::chrono::seconds::zero() || age > grace) {
    decision.reason = "grace_elapsed";
    return decision;
  }
  if (!signature_valid(stored.public_key_base64, stored.canonical, stored.signature_base64)) {
    decision.reason = "tampered";
    return decision;
  }
  EntitlementFields fields;
  if (!parse_entitlement(stored.canonical, fields)) {
    decision.reason = "malformed";
    return decision;
  }
  if (fields.status != "active") {
    decision.reason = "not_active";
    return decision;
  }
  if (fields.application_id != expected_application_id) {
    decision.reason = "application_mismatch";
    return decision;
  }
  if (fields.key_id != expected_key_id) {
    decision.reason = "key_mismatch";
    return decision;
  }
  std::chrono::system_clock::time_point expires_at;
  if (!parse_iso_utc(fields.expires_at, expires_at) || expires_at <= now) {
    decision.reason = "entitlement_expired";
    return decision;
  }
  decision.accepted = true;
  decision.reason = "accepted";
  return decision;
}

std::string serialize_cache(const StoredEntitlement& stored) {
  std::ostringstream out;
  out << "stored_at=" << stored.stored_at << "\n";
  out << "public_key=" << stored.public_key_base64 << "\n";
  out << "signature=" << stored.signature_base64 << "\n";
  out << kCanonicalPrefix << stored.canonical.size() << "\n";
  out << stored.canonical;
  return out.str();
}

std::optional<StoredEntitlement> parse_cache(std::string_view text) {
  StoredEntitlement stored;
  std::size_t cursor = 0;
  const auto take_line = [&](std::string_view& line) -> bool {
    if (cursor > text.size()) {
      return false;
    }
    const std::size_t end = text.find('\n', cursor);
    if (end == std::string_view::npos) {
      return false;
    }
    line = text.substr(cursor, end - cursor);
    cursor = end + 1;
    return true;
  };
  std::string_view line;
  if (!take_line(line) || !line.starts_with("stored_at=")) {
    return std::nullopt;
  }
  stored.stored_at = std::string(line.substr(std::string_view("stored_at=").size()));
  if (!take_line(line) || !line.starts_with("public_key=")) {
    return std::nullopt;
  }
  stored.public_key_base64 = std::string(line.substr(std::string_view("public_key=").size()));
  if (!take_line(line) || !line.starts_with("signature=")) {
    return std::nullopt;
  }
  stored.signature_base64 = std::string(line.substr(std::string_view("signature=").size()));
  if (!take_line(line) || !line.starts_with(kCanonicalPrefix)) {
    return std::nullopt;
  }
  const std::string length_text(line.substr(kCanonicalPrefix.size()));
  std::size_t length = 0;
  try {
    length = static_cast<std::size_t>(std::stoul(length_text));
  } catch (const std::exception&) {
    return std::nullopt;
  }
  if (text.size() - cursor != length) {
    return std::nullopt;
  }
  stored.canonical = std::string(text.substr(cursor));
  return stored;
}

}  // namespace kernauth
