# KernAuth C++ SDK

Open `KernAuth.sln`, paste the public app ID and public key from Developers, and run it. The program asks for a license key, then opens the sealed payload with the key from `validate`.

The library is the headers in `include/`. Include `kernauth.hpp`. There are no library source files to add. The project still links libsodium and libcurl.

## Visual Studio

Use Visual Studio 2022 with the Desktop development with C++ workload. That workload includes vcpkg.

1. Open `KernAuth.sln` in this folder.
2. In `src/main.cpp`, replace the public app ID and public key with the values from Developers.
3. In the dashboard, set the Payload key to `example-payload-key` and press Save.
4. Press F5. The first build installs libsodium, libcurl, and nlohmann/json through vcpkg.
5. Type the license key at the prompt.

Solution Explorer has Source Files (`src/main.cpp`, `src/unlock_key.cpp`, `src/unlock_program.cpp`) and Header Files (`src/unlock.hpp`, `src/sealed_payload.hpp`, and the `kernauth` headers).

The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_LICENSE_KEY` skips the prompt.

## Instance

```cpp
#include "kernauth.hpp"

kernauth::App app(
    "https://api.kernauth.com",
    "pub_your_app",
    "your_public_key");
```

Paste the public app ID and public key from Developers into `src/main.cpp`. The customer types the license key when the program runs. The library reads the Windows user SID.

## Validate

```cpp
kernauth::ClientResult result = app.validate(license_key);
std::string payload_key = unlock_payload_key(result.entitlement.features);
std::string message;
const bool opened = unlock_program(payload_key, message);
wipe_secret(payload_key);
```

`unlock_payload_key` opens the one-time lock inside the signed ticket and returns the dashboard payload key. `unlock_program` uses that key to open `src/sealed_payload.hpp`. The program prints `message`. That sentence is not stored in the source. This sample opens only when the saved payload key is `example-payload-key`. For a real program, seal your own bytes with your own key and replace that header. Leave the key out of the repository and out of the binary.

The one-time key is different on every validate and is not stored. Heartbeat does not mint another one. The offline cache rejects a ticket that contains it. Changing `validate` so it always returns success does not produce the sentence. A memory dump after a real login can still copy the opened key for that run. The example wipes it after opening the program, and wipes the sentence when the heartbeat fails.

The first success saves this computer. A later run on the same Windows user succeeds. Reset HWID in the dashboard clears it.

The program prints the opened text, the license state, the license id, and when this check stops being trusted. That expiry is at most 15 minutes, or sooner when the license itself ends first. It then asks the server again every minute. If the session was ended, the key was paused, or this computer is blocked, it prints that message and exits.

## Terminal build

CMake builds the same example. The first configure needs network access. It fetches libsodium, nlohmann/json, and libcurl.

```bash
cmake -S . -B build
cmake --build build
printf '%s\n' "YOUR-LICENSE-KEY" | ./build/kernauth
```

From the KernAuth monorepo, configure with `cmake -S packages/sdk-cpp -B build/sdk-cpp`.

Set the dashboard payload key to `example-payload-key` before running. Skipping the license check does not open the sealed bytes. A dump of the process after a successful login can still copy the key.

Documentation: https://kernauth.apidog.io
