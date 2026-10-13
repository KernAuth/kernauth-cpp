# KernAuth C++ SDK

Include one header. Construct `kernauth::App` with the values from Developers. Call `validate`. The last result is `response`.

The SDK checks the Ed25519 signature with libsodium. A patched binary can still skip that check. Revocation, device limits, and the audit log are enforced by the server. The SDK embeds no private signing key and no long-lived secret API key.

## Add it

The first configure needs network access. CMake fetches libsodium, nlohmann/json, and libcurl.

```powershell
cmake -S packages/sdk-cpp -B build/sdk-cpp -G "Visual Studio 18 2026" -A x64
cmake --build build/sdk-cpp --config Debug
```

Linux and macOS:

```bash
cmake -S packages/sdk-cpp -B build/sdk-cpp
cmake --build build/sdk-cpp
```

Link `kernauth_sdk` and include `kernauth.hpp`. The vector test is built only when this tree sits inside the KernAuth monorepo.

## Instance

`hide` encrypts the literal at compile time and returns the string. A plain strings dump does not show it. A compiler may still keep a copy. This is not protection.

```cpp
#include "kernauth.hpp"

kernauth::App app(
    hide("https://api.kernauth.com"),
    hide("pub_your_app"),
    hide("your_key_id"),
    hide("your_public_key"));
app.set_installation(hide("install_your_device"), "desktop");
```

Paste the public app ID, key ID, and public key from Developers. Pin those values in the client you ship. Do not download a different key at runtime. Persist one installation ID per device and reuse it. The Free plan allows one device. Pass the license key from your own prompt or a file. Do not commit a customer key.

## Validate

```cpp
if (!app.validate(license_key).active) {
  std::cout << app.response.message << "\n";
  return 1;
}
```

The first success saves this machine. A later call from the same installation succeeds. A different machine fails when the license has no free device slot. The Free plan has one slot. Reset HWID in the dashboard clears the saved machines. `response.message` is `License is active`. On failure, `response.ok` is false and `response.message` is the server error with the license key redacted.

Call this when the program starts, and before a privileged action. A revoked license is refused on the next validate, or when the signed entitlement expires.

## Example

`examples/main.cpp` is the program above.

```powershell
"YOUR-LICENSE-KEY" | .\build\sdk-cpp\Debug\kernauth.exe
```

```bash
printf '%s\n' "YOUR-LICENSE-KEY" | ./build/sdk-cpp/kernauth
```

A signed entitlement can stay valid for at most 15 minutes. After that, the next validate has to succeed. Documentation: https://kernauth.apidog.io
