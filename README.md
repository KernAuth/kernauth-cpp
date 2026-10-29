# KernAuth C++ SDK

Open `KernAuth.sln`, paste the public app ID and public key from Developers, and run it. The program asks for a license key, checks the signed ticket, and prints the license.

The library is the static archive built from `src/sdk`. Include `include/kernauth.hpp` and link libsodium and libcurl. `src/main.cpp` validates and heartbeats, and `src/secured.cpp` initializes, unwraps the payload, and downloads a file.

## Visual Studio

Use Visual Studio 2026 with the Desktop development with C++ workload. That workload includes vcpkg. The project toolset is v145.

1. Open `KernAuth.sln` in this folder.
2. In `src/main.cpp`, replace the public app ID and public key with the values from Developers.
3. Press F5. The first build installs libsodium, libcurl, and nlohmann/json through vcpkg.
4. Type the license key at the prompt.

Solution Explorer has Source Files (`src/main.cpp`) and Header Files (`include/kernauth.hpp` plus the `kernauth` headers).

The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_LICENSE_KEY` skips the prompt.

## Instance

```cpp
#include "kernauth.hpp"

kernauth::App app(
    "https://api.kernauth.com",
    "pub_your_app",
    "your_public_key",
    "1.0.0");
```

The last argument is the version sent to KernAuth. Leave it out when Require this version is off. Paste the public app ID and public key from Developers into `src/main.cpp`. The customer types the license key when the program runs. The library reads the Windows user SID.

## Validate

```cpp
kernauth::ClientResult result = app.validate(license_key);
if (!result.active) {
  return 1;
}
```

Call `initialize()` before `validate`. That derives a session secret from HWID, a random salt, and the server UTC hour. `validate` accepts the license only when the Ed25519 signature checks, the ticket belongs to this application, and it has not expired. When a payload key is configured, use `unwrap_payload()` to open `payload_box` with that session secret — `wrap_key` is never returned.

The program then calls `heartbeat` every minute. If the session was ended, the key was paused, or this computer is blocked, it prints that message and exits.

The first success saves this computer. A later run on the same Windows user succeeds. Reset HWID in the dashboard clears it. The check expiry is at most 15 minutes, or sooner when the license itself ends first. A patched check can still skip a local branch. The server can still revoke the license and end the session.

## Terminal build

CMake builds the same example. The first configure needs network access. It fetches libsodium, nlohmann/json, and libcurl.

```bash
cmake -S . -B build
cmake --build build
printf '%s\n' "YOUR-LICENSE-KEY" | ./build/kernauth
```

From the KernAuth monorepo, configure with `cmake -S packages/sdk-cpp -B build/sdk-cpp`.

Documentation: https://kernauth.apidog.io
