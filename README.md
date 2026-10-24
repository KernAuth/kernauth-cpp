# KernAuth C++ SDK (basic)

Header-only license check with vendored **libsodium**, **libcurl**, and **nlohmann/json** under `include/`, plus static libs in `lib/` (x64, Windows).

This sample does **not** use a payload key. For initialize → unwrap → sealed payload, open [kernauth-cpp-secured](https://github.com/KernAuth/kernauth-cpp-secured).

## Use

```cpp
#include "kernauth.hpp"

kernauth::App app(
    "https://api.kernauth.com",
    "pub_your_app",
    "your_public_key");
// The last argument is the version. Leave it out when Require this version is off.
// kernauth::App app(api, app_id, public_key, "1.0.0");

if (!app.initialize().ok) {
  return 1;
}

kernauth::ClientResult result = app.validate(license_key);
if (!result.active) {
  return 1;
}
```

Call `initialize()` before `validate` so the session salt and server time bucket are set. Paste the public app ID and public key from Developers into `src/main.cpp` (or your own file). The customer types the license at runtime. On Windows the library reads the signed-in user SID as HWID. `KERN_LICENSE_KEY` skips the prompt.

## Layout

| Path | What |
| --- | --- |
| `include/kernauth.hpp` | Public entry (`App`, `hide()`) |
| `include/kernauth/` | SDK headers |
| `include/curl/`, `include/sodium*`, `include/nlohmann/` | Vendored dependencies |
| `lib/` | `libcurl.lib`, `libsodium.lib`, `zlib.lib` (x64 static) |
| `src/main.cpp` | Basic validate + heartbeat example |

When linking your own project: add `include/` to includes, `lib/` to library dirs, define `CURL_STATICLIB` and `SODIUM_STATIC`, and link `libcurl`, `libsodium`, `zlib`, `ws2_32`, `crypt32`, `wldap32`, `normaliz`, `advapi32`.

A modified program can still skip the local check. The server can still revoke the license and end the session.

Documentation: https://kernauth.apidog.io
