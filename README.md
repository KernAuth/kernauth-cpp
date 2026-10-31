# KernAuth C++ SDK

`KernAuth.sln` builds the static library `kernauth.lib`. Your program is one project. Include `kernauth.hpp`, link `kernauth.lib`, and also link the libsodium and libcurl libraries that vcpkg built for this library. Start from `src/secured.cpp`.

`src/secured.cpp` asks for a license, validates it, and downloads one uploaded file. The plaintext stays in memory and is wiped before the program exits. It does not write that file and it does not load those bytes. `src/main.cpp` is the smaller example: validate, then heartbeat.

## Visual Studio

Use Visual Studio 2026 with the Desktop development with C++ workload. That workload includes vcpkg. The project toolset is v145. The solution has one project, and that project is the static library.

1. Open `KernAuth.sln` in this folder.
2. Build it. The first build installs libsodium, libcurl, and nlohmann/json through vcpkg and produces `kernauth.lib`.
3. In your own project, include `include/kernauth.hpp` and link `kernauth.lib` plus those vcpkg libraries.
4. Copy `src/secured.cpp`, `src/download_hold.cpp`, and `src/download_hold.hpp` into that project. Replace `__PUBLIC_APP_ID__` and `__PUBLIC_KEY__` with the values from Developers.

The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_LICENSE_KEY` skips the prompt. `download()` takes no file name. The sample does not write an output file.

## Download

```cpp
#include "kernauth.hpp"

kernauth::App app(
    "https://api.kernauth.com",
    hide("__PUBLIC_APP_ID__"),
    hide("__PUBLIC_KEY__"));

kernauth::ClientResult session = app.initialize();
kernauth::ClientResult result = app.validate(license_key);
kernauth::DownloadResult file = app.download();
// file.bytes is the plaintext. The sample wipes it and does not write it. Do not load it as a library.
```

## Payload key

`unwrap_payload()` opens `payload_box` from the last successful validate. The payload key arrives only inside that ticket. `wrap_key` is never returned.

```cpp
kernauth::PayloadUnwrap payload = app.unwrap_payload();
```

Call `initialize()` before `validate`. That derives a session secret from HWID, a random salt, and the server UTC hour. `validate` accepts the license only when the Ed25519 signature checks, the ticket belongs to this application, and it has not expired.

`src/main.cpp` then calls `heartbeat` every minute. If the session was ended, the key was paused, or this computer is blocked, it prints that message and exits.

The first success saves this computer. A later run on the same Windows user succeeds. Reset HWID in the dashboard clears it. The check expiry is at most 15 minutes, or sooner when the license itself ends first. A patched check can still skip a local branch. The server can still revoke the license and end the session.

## One build

Place the private bytes with KERNAUTH_SEAL. The running program ignores that section and calls `download()` after validate. `download()` takes no file name.

kernauth-seal --input app.exe

Set `KERN_AUTH_SEALER_KEY`. The seller generates that key on the Files card. It is shown once. Rotate replaces it. Starter can generate it. The tool uploads the sealed file and writes app.share.exe. It does not use `KERN_AUTH_API_KEY` or `KERN_AUTH_APP_ID`. A developer `ka_` key cannot upload the sealed file. Without the sealer key, pass `--no-upload --payload-out build.bin`. Share app.share.exe. Keep libcurl.dll and z.dll beside the sealer.

## Terminal build

CMake builds the library and `src/secured.cpp`. The first configure needs network access. It fetches libsodium, nlohmann/json, and libcurl.

```bash
cmake -S . -B build
cmake --build build --target secured
```

From the KernAuth monorepo, configure with `cmake -S packages/sdk-cpp -B build/sdk-cpp`.

Documentation: https://kernauth.apidog.io
