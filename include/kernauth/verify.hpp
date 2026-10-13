#pragma once

#include "kernauth/canonical.hpp"

#include <string>
#include <string_view>

namespace kernauth {

enum class GrantFailure {
  None = 0,
  BadSignature,
  NonceMismatch,
  ApplicationMismatch,
  KeyMismatch,
  NotActive,
  Expired,
  Malformed,
};

struct GrantExpectation {
  std::string_view application_id;
  std::string_view key_id;
  std::string_view nonce;
  std::string_view now_iso;
};

struct GrantDecision {
  bool active = false;
  GrantFailure failure = GrantFailure::Malformed;
};

/** Ed25519 verify over the exact canonical bytes. Uses libsodium. */
bool signature_valid(
    std::string_view public_key_base64,
    std::string_view message,
    std::string_view signature_base64);

/**
 * An active grant requires a valid signature plus the application id, key id,
 * nonce, active status, and an expiry that is still after `now_iso`.
 */
GrantDecision decide_grant(
    const EntitlementFields& fields,
    std::string_view signature_base64,
    std::string_view public_key_base64,
    const GrantExpectation& expected);

}  // namespace kernauth
