#pragma once

#include <string>
#include <string_view>

bool unwrap_payload_key(std::string_view wrap_key, std::string_view payload_box, std::string& payload_key);
bool open_sealed_payload(std::string_view payload_key, std::string& plain);
void wipe_secret(std::string& value);
