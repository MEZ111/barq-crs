# Android analysis

BARQ accepts either an APK/ZIP or a decoded Android directory:

```bash
barq mobile application.apk > mobile-findings.json
barq mobile decoded-application > mobile-findings.json
```

## What the engine inspects

| Layer | Evidence |
|---|---|
| Package inventory | DEX files, native libraries, signing entries, file count |
| Manifest | Release flags, exported activities/services/receivers/providers, declared permission boundaries |
| App links | VIEW/BROWSABLE routes, schemes, hosts, paths, verification state |
| Network policy | Release trust of user-installed CAs and cleartext configuration |
| WebView | JavaScript/native bridge combinations, file-origin access, remote debugging |
| TLS | Certificate-error continuation and permissive hostname-verifier combinations |
| Storage | World-readable/world-writeable modes |
| Embedded credentials | Provider/type plus SHA-256 fingerprint; the value is never emitted |

The APK reader enforces entry, expanded-size, per-entry, and compression-ratio
budgets. It reads entries in place and never extracts an archive. A built-in
decoder handles Android binary XML string pools, typed attributes, elements,
and namespaces, so manifest analysis does not require a third-party package.

## Evidence quality

A result is a review candidate, not automatic proof of impact. Manifest
findings identify reachability and missing declarative boundaries. Code
findings require correlated patterns in the same artifact entry. Confirmation
belongs on an emulator or a researcher-owned device with controlled data.

For deeper data-flow confirmation, decode the app locally with your preferred
tool and point BARQ at the decoded directory. BARQ then reports source file and
line locations in both JSON and SARIF.

## Deliberate limits

- No APK is installed or executed.
- No certificate pinning is bypassed.
- No credential value is printed, copied, or validated against a service.
- Native-code reachability is inventoried but not decompiled.
- Obfuscated call graphs still require human review.

These constraints keep the public engine reproducible while allowing a private
campaign repository to hold authorized emulator traces and program-specific
validation.
