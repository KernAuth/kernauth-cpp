#pragma once

#include <string>
#include <string_view>

bool open_sealed_payload(std::string_view payload_key, std::string& plain);
void wipe_secret(std::string& value);
