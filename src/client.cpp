#include "kernauth/client.hpp"

#include "kernauth/nonce.hpp"
#include "kernauth/verify.hpp"

#include <nlohmann/json.hpp>

namespace kernauth {
namespace {

std::string join_url(std::string_view base_url, std::string_view path) {
  std::string url(base_url);
  while (!url.empty() && url.back() == '/') {
    url.pop_back();
  }
  url.append(path);
  return url;
}

std::string redact_key(std::string message, std::string_view license_key) {
  if (!license_key.empty() && message.find(license_key) != std::string::npos) {
    return "License validation failed";
  }
  return message;
}

ClientResult failure_result(int status, std::string code, std::string message) {
  ClientResult result;
  result.http_status = status;
  result.code = std::move(code);
  result.message = std::move(message);
  return result;
}

ClientResult post_entitlement(
    HttpTransport& transport,
    const ClientOptions& options,
    std::string_view license_key,
    std::string_view path) {
  if (options.base_url.empty() || options.public_app_id.empty() || options.device_fingerprint.empty() ||
      options.installation_id.empty()) {
    return failure_result(0, "invalid_request", "Client options are incomplete");
  }
  const std::string nonce = options.nonce_generator ? options.nonce_generator() : random_nonce();
  const std::string now_iso = options.now_iso ? options.now_iso() : utc_now_iso();
  nlohmann::json body = {
      {"protocol_version", kProtocolVersion},
      {"public_app_id", options.public_app_id},
      {"client_version", options.client_version},
      {"license_key", license_key},
      {"fingerprint_version", options.fingerprint_version},
      {"device_fingerprint", options.device_fingerprint},
      {"installation_id", options.installation_id},
      {"nonce", nonce},
  };
  if (!options.device_label.empty()) {
    body["device_label"] = options.device_label;
  }

  HttpRequest request;
  request.method = "POST";
  request.url = join_url(options.base_url, path);
  request.body = body.dump();
  const HttpResponse response = transport.exchange(request);
  if (!response.transport_error.empty()) {
    return failure_result(0, "transport", "The license service could not be reached");
  }

  nlohmann::json parsed;
  try {
    parsed = nlohmann::json::parse(response.body);
  } catch (const nlohmann::json::exception&) {
    return failure_result(response.status, "malformed_response", "The license service returned invalid JSON");
  }

  if (response.status != 200) {
    std::string code = "license_invalid";
    std::string message = "License validation failed";
    if (parsed.contains("error") && parsed["error"].is_object()) {
      if (parsed["error"].contains("code") && parsed["error"]["code"].is_string()) {
        code = parsed["error"]["code"].get<std::string>();
      }
      if (parsed["error"].contains("message") && parsed["error"]["message"].is_string()) {
        message = redact_key(parsed["error"]["message"].get<std::string>(), license_key);
      }
    }
    auto result = failure_result(response.status, code, message);
    if (parsed.contains("error") && parsed["error"].contains("request_id") &&
        parsed["error"]["request_id"].is_string()) {
      result.request_id = parsed["error"]["request_id"].get<std::string>();
    }
    return result;
  }

  if (!parsed.contains("entitlement") || !parsed["entitlement"].is_object() || !parsed.contains("signature") ||
      !parsed["signature"].is_string()) {
    return failure_result(response.status, "malformed_response", "Entitlement response was incomplete");
  }
  const auto& entitlement = parsed["entitlement"];
  EntitlementFields fields;
  try {
    fields.protocol_version = entitlement.at("protocol_version").get<int>();
    fields.entitlement_id = entitlement.at("entitlement_id").get<std::string>();
    fields.application_id = entitlement.at("application_id").get<std::string>();
    fields.license_id = entitlement.at("license_id").get<std::string>();
    fields.status = entitlement.at("status").get<std::string>();
    fields.features = entitlement.at("features").dump();
    fields.device_id = entitlement.at("device_id").get<std::string>();
    fields.issued_at = entitlement.at("issued_at").get<std::string>();
    fields.expires_at = entitlement.at("expires_at").get<std::string>();
    fields.server_time = entitlement.at("server_time").get<std::string>();
    fields.nonce = entitlement.at("nonce").get<std::string>();
    fields.key_id = entitlement.at("key_id").get<std::string>();
  } catch (const nlohmann::json::exception&) {
    return failure_result(response.status, "malformed_response", "Entitlement fields were incomplete");
  }

  const std::string signature = parsed["signature"].get<std::string>();
  const GrantDecision decision = decide_grant(
      fields,
      signature,
      options.public_key_base64,
      GrantExpectation{
          .application_id = options.public_app_id,
          .key_id = options.key_id,
          .nonce = nonce,
          .now_iso = now_iso,
      });
  ClientResult result;
  result.http_status = response.status;
  result.entitlement = fields;
  result.signature_base64 = signature;
  if (parsed.contains("request_id") && parsed["request_id"].is_string()) {
    result.request_id = parsed["request_id"].get<std::string>();
  }
  if (!decision.active) {
    result.code = "not_active";
    result.message = "Entitlement was not accepted";
    return result;
  }
  result.ok = true;
  result.active = true;
  result.code = "active";
  return result;
}

}  // namespace

VersionInfo fetch_version(HttpTransport& transport, std::string_view base_url) {
  HttpRequest request;
  request.method = "GET";
  request.url = join_url(base_url, "/v1/client/version");
  const HttpResponse response = transport.exchange(request);
  VersionInfo info;
  info.http_status = response.status;
  if (!response.transport_error.empty()) {
    info.code = "transport";
    info.message = "The license service could not be reached";
    return info;
  }
  try {
    const auto parsed = nlohmann::json::parse(response.body);
    if (response.status != 200) {
      info.code = "version_failed";
      info.message = "Version request failed";
      return info;
    }
    info.protocol_version = parsed.at("protocol_version").get<int>();
    info.key_id = parsed.at("key_id").get<std::string>();
    info.public_key_base64 = parsed.at("public_key").get<std::string>();
    if (parsed.contains("request_id") && parsed["request_id"].is_string()) {
      info.request_id = parsed["request_id"].get<std::string>();
    }
    if (info.protocol_version != kProtocolVersion || info.key_id.empty() || info.public_key_base64.empty() ||
        parsed.contains("private_key")) {
      info.code = "malformed_response";
      info.message = "Version response was not usable";
      return info;
    }
    info.ok = true;
    info.code = "ok";
    return info;
  } catch (const nlohmann::json::exception&) {
    info.code = "malformed_response";
    info.message = "Version response was not JSON";
    return info;
  }
}

ClientResult validate_license(
    HttpTransport& transport,
    const ClientOptions& options,
    std::string_view license_key) {
  return post_entitlement(transport, options, license_key, "/v1/client/validate");
}

}  // namespace kernauth
