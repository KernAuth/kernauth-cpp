#include "kernauth.hpp"
#include "kernauth/cache.hpp"
#include "kernauth/canonical.hpp"
#include "kernauth/client.hpp"
#include "kernauth/nonce.hpp"
#include "kernauth/verify.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void pass(const std::string& label) {
  std::cout << "PASS " << label << "\n";
}

void fail(const std::string& label) {
  std::cout << "FAIL " << label << "\n";
  ++g_failures;
}

void expect(bool condition, const std::string& label) {
  if (condition) {
    pass(label);
  } else {
    fail(label);
  }
}

class ScriptedTransport final : public kernauth::HttpTransport {
 public:
  std::vector<kernauth::HttpRequest> requests;
  std::function<kernauth::HttpResponse(const kernauth::HttpRequest&)> handler;

  kernauth::HttpResponse exchange(const kernauth::HttpRequest& request) override {
    requests.push_back(request);
    if (!handler) {
      kernauth::HttpResponse response;
      response.transport_error = "no scripted response";
      return response;
    }
    return handler(request);
  }
};

std::string base64_encode(const unsigned char* data, std::size_t size) {
  const std::size_t encoded_size = sodium_base64_ENCODED_LEN(size, sodium_base64_VARIANT_ORIGINAL);
  std::string encoded(encoded_size, '\0');
  sodium_bin2base64(encoded.data(), encoded.size(), data, size, sodium_base64_VARIANT_ORIGINAL);
  encoded.resize(std::strlen(encoded.c_str()));
  return encoded;
}

class TestSigningKey {
 public:
  TestSigningKey() {
    if (sodium_init() < 0) {
      throw std::runtime_error("libsodium failed to initialize");
    }
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    if (crypto_sign_keypair(public_key, secret_.data()) != 0) {
      throw std::runtime_error("libsodium could not create a test keypair");
    }
    public_key_base64_ = base64_encode(public_key, sizeof(public_key));
  }

  TestSigningKey(const TestSigningKey&) = delete;
  TestSigningKey& operator=(const TestSigningKey&) = delete;

  ~TestSigningKey() {
    sodium_memzero(secret_.data(), secret_.size());
  }

  const std::string& public_key_base64() const {
    return public_key_base64_;
  }

  std::string sign(std::string_view message) const {
    unsigned char signature[crypto_sign_BYTES];
    if (crypto_sign_detached(
            signature,
            nullptr,
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            secret_.data()) != 0) {
      throw std::runtime_error("libsodium could not sign the test entitlement");
    }
    return base64_encode(signature, sizeof(signature));
  }

 private:
  std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_{};
  std::string public_key_base64_;
};

kernauth::EntitlementFields fields_from_vector(const nlohmann::json& item) {
  const auto& fields = item.at("fields");
  kernauth::EntitlementFields parsed;
  parsed.protocol_version = fields.at("protocol_version").get<int>();
  parsed.entitlement_id = fields.at("entitlement_id").get<std::string>();
  parsed.application_id = fields.at("application_id").get<std::string>();
  parsed.license_id = fields.at("license_id").get<std::string>();
  parsed.status = fields.at("status").get<std::string>();
  parsed.features = fields.at("features").get<std::string>();
  parsed.device_id = fields.at("device_id").get<std::string>();
  parsed.issued_at = fields.at("issued_at").get<std::string>();
  parsed.expires_at = fields.at("expires_at").get<std::string>();
  parsed.server_time = fields.at("server_time").get<std::string>();
  parsed.nonce = fields.at("nonce").get<std::string>();
  parsed.key_id = fields.at("key_id").get<std::string>();
  return parsed;
}

kernauth::GrantExpectation expectation_for(const kernauth::EntitlementFields& fields, std::string_view now_iso) {
  kernauth::GrantExpectation expected;
  expected.application_id = fields.application_id;
  expected.key_id = fields.key_id;
  expected.nonce = fields.nonce;
  expected.now_iso = now_iso;
  return expected;
}

nlohmann::json worker_success(const nlohmann::json& item) {
  nlohmann::json entitlement = item.at("fields");
  entitlement["features"] = nlohmann::json::parse(item.at("fields").at("features").get<std::string>());
  return nlohmann::json{
      {"entitlement", entitlement},
      {"signature", item.at("signature").get<std::string>()},
      {"request_id", "req_vector"},
  };
}

kernauth::ClientOptions options_for(const nlohmann::json& item, const std::string& fingerprint) {
  const auto fields = fields_from_vector(item);
  kernauth::ClientOptions options;
  options.base_url = "http://127.0.0.1:8787";
  options.public_app_id = fields.application_id;
  options.public_key_base64 = item.at("public_key").get<std::string>();
  options.key_id = fields.key_id;
  options.device_fingerprint = fingerprint;
  options.installation_id = "install_sdk_test";
  options.device_label = "sdk-test";
  options.nonce_generator = [nonce = fields.nonce]() { return nonce; };
  options.now_iso = []() { return std::string("2026-01-01T00:00:00.000Z"); };
  return options;
}

bool nonce_charset_ok(std::string_view nonce) {
  if (nonce.size() < 16 || nonce.size() > 128) {
    return false;
  }
  for (const char character : nonce) {
    const bool digit = character >= '0' && character <= '9';
    const bool upper = character >= 'A' && character <= 'Z';
    const bool lower = character >= 'a' && character <= 'z';
    if (!digit && !upper && !lower && character != '_' && character != '-') {
      return false;
    }
  }
  return true;
}

void check_conceal() {
  constexpr char plain[] = "api.kernauth.com";
  constexpr kernauth::ConcealedString<sizeof(plain), 0xC0FFEE1234ull> hidden(plain);
  const std::string revealed = hidden.reveal();
  expect(revealed == plain, "concealed string reveals the original");
  bool differs = false;
  for (std::size_t index = 0; index < sizeof(plain); ++index) {
    if (hidden.stored(index) != static_cast<unsigned char>(plain[index])) {
      differs = true;
    }
  }
  expect(differs, "concealed bytes differ from the plaintext");
  constexpr kernauth::ConcealedString<sizeof(plain), 0x123456789ull> other(plain);
  expect(hidden.stored(0) != other.stored(0), "a different seed stores different ciphertext");
  const std::string via_macro = hide("license-check");
  expect(via_macro == "license-check", "hide returns the literal");
}

void check_vectors(const nlohmann::json& document) {
  const auto& vectors = document.at("vectors");
  expect(vectors.is_array() && vectors.size() >= 2, "committed vectors are present");
  for (const auto& item : vectors) {
    const std::string name = item.at("name").get<std::string>();
    const auto fields = fields_from_vector(item);
    const std::string canonical = kernauth::encode_entitlement(fields);
    const std::string committed = item.at("canonical").get<std::string>();
    if (canonical == committed) {
      std::cout << "VECTOR_CANONICAL_BYTES " << name << "\n";
      std::cout << canonical;
      pass("vector " + name + " canonical bytes match the committed vector");
    } else {
      fail("vector " + name + " canonical bytes match the committed vector");
    }
    const bool verified = kernauth::signature_valid(
        item.at("public_key").get<std::string>(),
        canonical,
        item.at("signature").get<std::string>());
    expect(verified, "vector " + name + " signature verifies");
  }

  const auto& active = vectors.at(0);
  auto fields = fields_from_vector(active);
  const std::string canonical = kernauth::encode_entitlement(fields);
  std::string tampered = canonical;
  const std::string original_nonce = "nonce_vector_0001";
  const std::string mutated_nonce = "nonce_vector_9999";
  const auto nonce_at = tampered.find(original_nonce);
  expect(nonce_at != std::string::npos, "active vector contains the committed nonce");
  if (nonce_at != std::string::npos) {
    tampered.replace(nonce_at, original_nonce.size(), mutated_nonce);
  }
  expect(
      !kernauth::signature_valid(active.at("public_key").get<std::string>(), tampered, active.at("signature").get<std::string>()),
      "tampered nonce signature fails");

  fields.nonce = mutated_nonce;
  const auto tampered_decision = kernauth::decide_grant(
      fields,
      active.at("signature").get<std::string>(),
      active.at("public_key").get<std::string>(),
      expectation_for(fields_from_vector(active), "2026-01-01T00:00:00.000Z"));
  expect(!tampered_decision.active, "tampered nonce is not active");

  const auto valid_fields = fields_from_vector(active);
  const std::string signature = active.at("signature").get<std::string>();
  const std::string public_key = active.at("public_key").get<std::string>();
  auto expected = expectation_for(valid_fields, "2026-01-01T00:00:00.000Z");
  expect(
      kernauth::decide_grant(valid_fields, signature, public_key, expected).active,
      "committed active vector is an active grant before expiry");

  expected.application_id = "pub_other_app_0001";
  expect(
      !kernauth::decide_grant(valid_fields, signature, public_key, expected).active,
      "wrong application id is not active");

  expected = expectation_for(valid_fields, "2026-01-01T00:00:00.000Z");
  expected.key_id = "kern-other-key";
  expect(!kernauth::decide_grant(valid_fields, signature, public_key, expected).active, "wrong key id is not active");

  auto revoked = valid_fields;
  revoked.status = "revoked";
  expect(
      !kernauth::decide_grant(revoked, signature, public_key, expectation_for(valid_fields, "2026-01-01T00:00:00.000Z")).active,
      "non-active status is not active");

  expect(
      !kernauth::decide_grant(valid_fields, signature, public_key, expectation_for(valid_fields, valid_fields.expires_at)).active,
      "past expiry is not active");
}

void check_http(const nlohmann::json& active) {
  const std::string fingerprint = kernauth::derive_device_fingerprint(1, "install_sdk_test");
  expect(fingerprint.size() == 64, "derived fingerprint is 64 hex characters");
  const std::string license_key = "KERN-TEST-KEY1-KEY1-KEY1";
  ScriptedTransport transport;
  transport.handler = [&](const kernauth::HttpRequest& request) {
    kernauth::HttpResponse response;
    response.status = 200;
    response.body = worker_success(active).dump();
    return response;
  };

  const auto options = options_for(active, fingerprint);
  const auto validated = kernauth::validate_license(transport, options, license_key);
  expect(validated.ok && validated.active && validated.code == "active", "validate accepts the committed active vector");
  expect(!transport.requests.empty() && transport.requests.back().url.find("/v1/client/validate") != std::string::npos,
         "validate posts to the client validate route");

  kernauth::App app(transport, options);
  app.validate(license_key);
  expect(app.response.ok && app.response.active && app.response.message == "License is active",
         "app facade stores a successful validate");

  transport.handler = [&](const kernauth::HttpRequest&) {
    kernauth::HttpResponse response;
    response.status = 403;
    nlohmann::json body = {
        {"error",
         {{"code", "license_invalid"},
          {"message", std::string("rejected ") + license_key},
          {"request_id", "req_fail"}}},
    };
    response.body = body.dump();
    return response;
  };
  const char* failure_labels[] = {"unknown key", "revoked key", "expired key"};
  for (const char* label : failure_labels) {
    const auto rejected = kernauth::validate_license(transport, options, license_key);
    expect(!rejected.ok && !rejected.active && rejected.code == "license_invalid", std::string(label) + " is not an active grant");
    expect(rejected.message.find(license_key) == std::string::npos, std::string(label) + " result does not contain the raw license key");
  }

  ScriptedTransport nonce_transport;
  nonce_transport.handler = [](const kernauth::HttpRequest&) {
    kernauth::HttpResponse response;
    response.status = 403;
    response.body = R"({"error":{"code":"license_invalid","message":"License validation failed","request_id":"req_nonce"}})";
    return response;
  };
  kernauth::ClientOptions fresh = options;
  fresh.nonce_generator = nullptr;
  const auto first = kernauth::validate_license(nonce_transport, fresh, license_key);
  const auto second = kernauth::validate_license(nonce_transport, fresh, license_key);
  expect(!first.active && !second.active, "unverified responses are not active grants");
  expect(nonce_transport.requests.size() == 2, "two validate calls recorded two requests");
  if (nonce_transport.requests.size() == 2) {
    const auto first_body = nlohmann::json::parse(nonce_transport.requests[0].body);
    const auto second_body = nlohmann::json::parse(nonce_transport.requests[1].body);
    const std::string first_nonce = first_body.at("nonce").get<std::string>();
    const std::string second_nonce = second_body.at("nonce").get<std::string>();
    expect(first_nonce != second_nonce, "request nonces differ");
    expect(nonce_charset_ok(first_nonce) && nonce_charset_ok(second_nonce), "request nonces match the client nonce charset");
    expect(first_body.at("protocol_version").get<int>() == 1, "validate sends protocol version 1");
    expect(first_body.at("public_app_id").get<std::string>() == options.public_app_id, "validate sends the public application id");
    expect(first_body.at("device_fingerprint").get<std::string>() == fingerprint, "validate sends the derived fingerprint");
    expect(first_body.at("save_hwid").get<bool>() == true, "validate saves the HWID");
    expect(first_body.at("installation_id").get<std::string>() == "install_sdk_test", "validate sends the installation id");
  }
}

kernauth::EntitlementFields cache_fields(
    std::string_view application_id,
    std::string_view key_id,
    std::string_view issued_at,
    std::string_view expires_at) {
  kernauth::EntitlementFields fields;
  fields.protocol_version = 1;
  fields.entitlement_id = "ent_cache_0001";
  fields.application_id = std::string(application_id);
  fields.license_id = "lic_cache_0001";
  fields.status = "active";
  fields.features = "{}";
  fields.device_id = "dev_cache_0001";
  fields.issued_at = std::string(issued_at);
  fields.expires_at = std::string(expires_at);
  fields.server_time = std::string(issued_at);
  fields.nonce = "nonce_cache_000001";
  fields.key_id = std::string(key_id);
  return fields;
}

kernauth::StoredEntitlement sign_cache(
    const TestSigningKey& key,
    const kernauth::EntitlementFields& fields,
    std::string_view stored_at) {
  kernauth::StoredEntitlement stored;
  stored.canonical = kernauth::encode_entitlement(fields);
  stored.signature_base64 = key.sign(stored.canonical);
  stored.public_key_base64 = key.public_key_base64();
  stored.stored_at = std::string(stored_at);
  return stored;
}

void check_cache() {
  expect(kernauth::kDefaultOfflineGrace == std::chrono::hours{72}, "default offline grace is 72 hours");
  std::chrono::system_clock::time_point stored_tp;
  expect(kernauth::parse_iso_utc("2026-06-01T00:00:00.000Z", stored_tp), "cache anchor time parses");
  const std::string stored_at = kernauth::format_iso_utc(stored_tp);
  expect(stored_at == "2026-06-01T00:00:00.000Z", "cache anchor time round-trips");
  const auto expires_tp = stored_tp + std::chrono::hours{24 * 30};
  const std::string expires_at = kernauth::format_iso_utc(expires_tp);
  const std::string inside = kernauth::format_iso_utc(stored_tp + kernauth::kDefaultOfflineGrace - std::chrono::hours{1});
  const std::string boundary = kernauth::format_iso_utc(stored_tp + kernauth::kDefaultOfflineGrace);
  const std::string elapsed = kernauth::format_iso_utc(stored_tp + kernauth::kDefaultOfflineGrace + std::chrono::seconds{1});

  TestSigningKey key;
  const std::string application_id = "pub_cache_app_0001";
  const std::string key_id = "kern-cache-test";
  const auto stored = sign_cache(key, cache_fields(application_id, key_id, stored_at, expires_at), stored_at);
  expect(
      kernauth::signature_valid(stored.public_key_base64, stored.canonical, stored.signature_base64),
      "in-process cache signature verifies through the sdk");

  const auto accepted = kernauth::evaluate_offline_cache(stored, application_id, key_id, inside);
  expect(accepted.accepted && accepted.reason == "accepted", "cache accepts a verified unexpired entitlement inside the 72-hour grace");
  const auto at_boundary = kernauth::evaluate_offline_cache(stored, application_id, key_id, boundary);
  expect(at_boundary.accepted, "cache accepts a verified entitlement at the 72-hour grace boundary");
  const auto too_old = kernauth::evaluate_offline_cache(stored, application_id, key_id, elapsed);
  expect(!too_old.accepted && too_old.reason == "grace_elapsed", "cache rejects elapsed grace");

  const std::string expired_now = kernauth::format_iso_utc(stored_tp + std::chrono::hours{1});
  const auto expired_grant = sign_cache(key, cache_fields(application_id, key_id, stored_at, stored_at), stored_at);
  const auto expired = kernauth::evaluate_offline_cache(expired_grant, application_id, key_id, expired_now);
  expect(!expired.accepted && expired.reason == "entitlement_expired", "cache rejects passed entitlement expiry");

  auto wrapped_fields = cache_fields(application_id, key_id, stored_at, expires_at);
  wrapped_fields.features = "{\"payload_box\":\"bbbb\",\"wrap_key\":\"aaaa\"}";
  const auto wrapped_grant = sign_cache(key, wrapped_fields, stored_at);
  const auto wrapped = kernauth::evaluate_offline_cache(wrapped_grant, application_id, key_id, inside);
  expect(!wrapped.accepted && wrapped.reason == "payload_wrap", "cache rejects a one-time payload wrap");

  auto tampered_bytes = stored;
  const auto marker = tampered_bytes.canonical.find("ent_cache_0001");
  expect(marker != std::string::npos, "cache canonical contains the entitlement id");
  if (marker != std::string::npos) {
    tampered_bytes.canonical.replace(marker, std::string("ent_cache_0001").size(), "ent_cache_0002");
  }
  const auto tampered = kernauth::evaluate_offline_cache(tampered_bytes, application_id, key_id, inside);
  expect(!tampered.accepted && tampered.reason == "tampered", "cache rejects tampered cache bytes");

  auto tampered_signature = stored;
  if (!tampered_signature.signature_base64.empty()) {
    tampered_signature.signature_base64[0] = tampered_signature.signature_base64[0] == 'A' ? 'B' : 'A';
  }
  const auto bad_signature = kernauth::evaluate_offline_cache(tampered_signature, application_id, key_id, inside);
  expect(!bad_signature.accepted && bad_signature.reason == "tampered", "cache rejects a tampered signature");

  const std::string serialized = kernauth::serialize_cache(stored);
  expect(serialized.find("KERN-") == std::string::npos, "cache does not store a raw license key");
  const auto parsed = kernauth::parse_cache(serialized);
  expect(parsed.has_value() && parsed->canonical == stored.canonical, "cache round-trips the signed canonical bytes");
  if (parsed.has_value()) {
    const auto reread = kernauth::evaluate_offline_cache(*parsed, application_id, key_id, inside);
    expect(reread.accepted, "cache accepts the round-tripped signed record inside grace");
  }
}

}  // namespace

int main() {
  try {
    std::ifstream input(KERNAUTH_VECTORS_JSON, std::ios::binary);
    if (!input) {
      fail("read committed entitlement vectors");
      return 1;
    }
    const auto document = nlohmann::json::parse(input);
    check_conceal();
    check_vectors(document);
    check_http(document.at("vectors").at(0));
    check_cache();
  } catch (const std::exception& error) {
    fail(std::string("unexpected exception: ") + error.what());
  }
  if (g_failures != 0) {
    std::cout << "FAILURES " << g_failures << "\n";
    return 1;
  }
  std::cout << "SDK_TESTS_OK\n";
  return 0;
}
