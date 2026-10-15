#pragma once

#include <string>

namespace kernauth {

/** Windows user SID, or KERN_INSTALLATION_ID when that override is set. Empty when neither is usable. */
std::string default_installation_id();

}  // namespace kernauth
