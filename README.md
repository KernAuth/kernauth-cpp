# KernAuth C++ SDK

Open the example, paste the public app ID and public key from Developers, and run it. The program asks for a license key, then prints the status, feature flags, license id, and when this check expires.

The library is the headers in `include/`. Include `kernauth.hpp`. There are no library source files to add. The project still links libsodium and libcurl.

## Visual Studio

Use Visual Studio 2022 with the Desktop development with C++ workload. That workload includes vcpkg.

1. Open `examples/vs/example.sln`.
2. In `examples/main.cpp`, replace the public app ID and public key with the values from Developers.
3. Press F5. The first build installs libsodium, libcurl, and nlohmann/json through vcpkg.
4. Type the license key at the prompt.

The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_LICENSE_KEY` skips the prompt.

## Instance

```cpp
#include "kernauth.hpp"

kernauth::App app(
    "https://api.kernauth.com",
    "pub_your_app",
    "your_public_key");
```

Paste the public app ID and public key from Developers into `examples/main.cpp`. The customer types the license key when the program runs. The library reads the Windows user SID.

## Validate

```cpp
const kernauth::ClientResult result = app.validate(license_key);
if (!result.active) {
  std::cout << result.message << "\n";
  return 1;
}
std::cout << "Status: " << result.entitlement.status << "\n";
std::cout << "Features: " << result.entitlement.features << "\n";
std::cout << "License: " << result.entitlement.license_id << "\n";
std::cout << "Check expires: " << result.entitlement.expires_at << "\n";
```

The first success saves this computer. A later run on the same Windows user succeeds. Reset HWID in the dashboard clears it.

`Status` is the license state. `Features` is the flags stored on that license. `License` is the license id. `Check expires` is when this check stops being trusted. That is at most 15 minutes, or sooner when the license itself ends first. The example then asks the server again every minute. If the session was ended, the key was paused, or this computer is blocked, it prints that message and exits.

## Terminal build

CMake builds the same example. The first configure needs network access. It fetches libsodium, nlohmann/json, and libcurl.

```bash
cmake -S . -B build
cmake --build build
printf '%s\n' "YOUR-LICENSE-KEY" | ./build/kernauth
```

From the KernAuth monorepo, configure with `cmake -S packages/sdk-cpp -B build/sdk-cpp`.

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
