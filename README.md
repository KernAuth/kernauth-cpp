# KernAuth C++ SDK (basic)

Header-only license check. Copy `include/` into your project, link **libsodium**, **libcurl**, and **nlohmann/json**, then call validate.

This sample does **not** use a payload key. For initialize → unwrap → sealed payload, use [kernauth-cpp-secured](https://github.com/KernAuth/kernauth-cpp-secured).

## Use

```cpp
#include "kernauth.hpp"

kernauth::App app(
    "https://api.kernauth.com",
    "pub_your_app",
    "your_public_key");

kernauth::ClientResult result = app.validate(license_key);
if (!result.active) {
  return 1;
}
```

Paste the public app ID and public key from Developers into `src/main.cpp` (or your own file). The customer types the license at runtime. On Windows the library reads the signed-in user SID as HWID. `KERN_LICENSE_KEY` skips the prompt.

`validate` accepts the license when the Ed25519 signature checks, the ticket belongs to this application, and it has not expired. The sample then heartbeats every minute. If the session ended, the key was paused, or this computer is blocked, it prints that and exits.

A modified program can still skip the local check. The server can still revoke the license and end the session.

## Layout

| Path | What |
| --- | --- |
| `include/kernauth.hpp` | Public entry (`App`, `hide()`) |
| `include/kernauth/` | Headers |
| `src/main.cpp` | Basic validate + heartbeat example |

Link against libsodium, libcurl, and nlohmann/json yourself (vcpkg, system packages, or vendored trees). There is no vcpkg manifest and no Visual Studio solution in this package.

Documentation: https://kernauth.apidog.io
