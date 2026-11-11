# Pinned Trivy native-output regression

`trivy-0.76.1-go-sbom.json` is the **unmodified native stdout** from the real
Trivy v0.76.1 binary in PR #12's network-disabled scan of an authored local
CycloneDX SBOM containing `github.com/gogo/protobuf@1.3.1`.

- Baseline head: `dfdfd283972fdea23b89985a50f0d76115e22731`
- Tested merge: `c6ff5db2d5f46786066be9ce081d4e551d4a2686`
- Run: https://github.com/knowlet/artex-ymh/actions/runs/41599255318
- Artifact: `13213417286` (`local-scanner-evidence-c6ff5db2d5f46786066be9ce081d4e551d4a2686`)
- Member: `local-scanner-evidence/trivy-vulnerable/native.json`
- Native SHA-256: `7ab8b1be90eb636b24dcf0cb65bb629e169e0415192d336f8525677b339e1ec3`
- Binary SHA-256: `d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83`
- Upstream commit: `e713f67f7d54decdcd9b3132c9751833dcced698`

The native process exited zero and reported the advisory, but ARTEX rejected
`Type: gobinary` because the parser only allowed `gomod`. The parser now accepts
both Go labels, without enabling executable, image or source-tree scans. It
still requires all input identities in explicit package inventories. An advisory
cannot substitute for a missing inventory entry or refer to another result's
inventory. Wrong-shaped vulnerability lists fail instead of becoming empty
success. `VendorIDs` are retained as aliases, not additional findings.

`test_trivy_inventory.py` checks this fixture's byte hash and replays it offline.
Its altered reports are **synthetic contract tests**, not additional real scans.
Real acceptance remains a separate gate: `scripts/verify_local_scanners.py`
installs the pinned binaries, checks deterministic/offline-cache packaging,
prepares DBs explicitly, and runs vulnerable, synthetic no-advisory and mixed
(two-package) SBOMs through ARTEX. It preserves input/native/result bytes and
checks denied authorization and corrupt/stale/missing DBs. Inspect the exact
candidate head's Actions result; this historical failing fixture is not proof
that a later candidate passed installation or end-to-end execution.
