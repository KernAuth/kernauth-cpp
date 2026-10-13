# KernAuth C++ SDK

C++20 client for a KernAuth application. You construct one `kernauth::App`, pass the license key, and check `response`. The SDK verifies the Ed25519 signature with libsodium over the same canonical bytes the server signs.

A patched binary can still skip that check. KernAuth's job is revocation, device limits, and the audit log. The SDK embeds no private signing key and no long-lived secret API key.

## Add it

Configure needs network access the first time. CMake fetches libsodium, nlohmann/json, and libcurl.

```powershell
cmake -S packages/sdk-cpp -B build/sdk-cpp -G "Visual Studio 18 2026" -A x64
cmake --build build/sdk-cpp --config Debug
```

Linux and macOS:

```bash
cmake -S packages/sdk-cpp -B build/sdk-cpp
cmake --build build/sdk-cpp
```

Link `kernauth_sdk` from your own target, or start from `examples/integrate.cpp`. The vector test is built only when this tree sits inside the KernAuth monorepo.

## Instance

Copy the public app ID, key ID, and public key from Developers. Pin them in the client you ship. Do not download a different key at runtime.

`KERNAUTH_CONCEAL` encrypts those literals at compile time so a plain strings dump does not show them. A compiler may still keep a copy. This is not protection.

```cpp
#include "kernauth/app.hpp"
#include "kernauth/conceal.hpp"

const std::string base_url = KERNAUTH_CONCEAL("https://api.kernauth.com").reveal();
const std::string app_id = KERNAUTH_CONCEAL("pub_your_app").reveal();
const std::string key_id = KERNAUTH_CONCEAL("your_key_id").reveal();
const std::string public_key = KERNAUTH_CONCEAL("your_public_key").reveal();

kernauth::App app(base_url, app_id, key_id, public_key);
app.set_installation("install_your_device", "desktop");
```

Persist one installation ID per device and reuse it. The Free plan allows one device. A second fingerprint is rejected. Pass the license key from your own prompt or a file. Do not commit a customer key.

## Activate

```cpp
app.activate(license_key);
if (!app.response.ok || !app.response.active) {
  std::cout << app.response.message << "\n";
  return 1;
}
```

`response.code` is `active` on success. `response.message` is `License is active`. On failure, `response.ok` is false and `response.message` is the server error with the license key redacted.

## Validate

Call this when the program starts again, and before a privileged action. The signed entitlement expires quickly. A revoked license is refused on the next validate, or when that signature expires.

```cpp
app.validate(license_key);
if (!app.response.active) {
  std::cout << app.response.message << "\n";
  return 1;
}
```

## Deactivate

This frees the device slot.

```cpp
app.deactivate(license_key);
if (!app.response.ok) {
  std::cout << app.response.message << "\n";
  return 1;
}
```

`response.message` is `Device deactivated`.

## Drop-in sample

`examples/integrate.cpp` is the program above. Build it and pipe the license key on stdin:

```powershell
"YOUR-LICENSE-KEY" | .\build\sdk-cpp\Debug\kernauth_integrate.exe
```

## CLI sample

`kernauth_example` takes the same values as flags when you do not want them compiled in. The default API URL is still concealed.

```powershell
$fp = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"YOUR-LICENSE-KEY" | .\build\sdk-cpp\Debug\kernauth_example.exe --public-app-id pub_your_app --key-id YOUR_KEY_ID --public-key YOUR_PUBLIC_KEY --fingerprint $fp
```

Repeat with `--mode validate`, then `--mode deactivate`. `--cache path` writes the signed local cache. The cache holds the canonical bytes, the signature, and the public key. It does not hold the raw license key. Offline use stops at the signed expiry, which is at most 15 minutes.

## What this does not do

There is no anti-debug, anti-VM, or import hiding. Those do not survive a patched binary, and this SDK does not pretend they do. Documentation: https://kernauth.apidog.io
