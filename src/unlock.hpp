#pragma once

#include <string>
#include <string_view>

// Opens the one-time lock in the signed ticket and wipes those fields.
// Returns the dashboard payload key for this login only.
std::string unlock_payload_key(std::string& features_json);

// Opens src/sealed_payload.hpp with that key. The sentence is not in the source.
bool unlock_program(std::string_view payload_key, std::string& message);

void wipe_secret(std::string& value);
