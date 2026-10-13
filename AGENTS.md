# C++ SDK

Parent rules are in the root `AGENTS.md`.

- C++20. The SDK verifies an Ed25519 entitlement with libsodium. It may embed a public application id and a public key. It must not embed a private key, a Worker secret, or a raw license key in the binary as a credential store.
- Do not describe the client as unbreakable. A patched binary can skip the local check. The server still expires entitlements, enforces device slots, and can revoke.
- The verified entitlement may be cached for 72 hours. Server entitlement lifetime stays 15 minutes.
- Build and test from the repo root with CMake, as `packages/sdk-cpp/README.md` describes. The first configure fetches libsodium and libcurl.
