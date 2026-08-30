# Target graph evidence

Use target graph inspection before attributing a source signal, manifest, entitlement, or dependency to a shipped product. Repository-wide matches without target membership are leads, not target-specific findings.

## Evidence order

1. Parse `PBXSourcesBuildPhase` and `PBXResourcesBuildPhase` membership without executing project code.
2. When explicitly enabled, collect `xcodebuild -list -json` and `xcodebuild -showBuildSettings -json` with automatic package resolution disabled.
3. Normalize only decision-relevant settings: `PRODUCT_BUNDLE_IDENTIFIER`, `WRAPPER_EXTENSION`, `MACH_O_TYPE`, `SUPPORTED_PLATFORMS`, `CONFIGURATION`, `TARGET_BUILD_DIR`, `EXECUTABLE_PATH`, product name, and Info.plist path.
4. Prefer Archive evidence over build settings for the submitted artifact.

The stable relation is:

```text
source/resource → target → configuration → product → bundle ID → executable → manifest
```

Keep absolute build roots tokenized. Generated projects, file-system-synchronized groups, build-tool-generated sources, and configuration-dependent membership may remain `NEEDS_VERIFY`; record that limitation instead of inventing membership.

Static library source ownership can be established from target membership. Attribution of code already linked into a final executable requires a Link Map or equivalent linker evidence; filename or symbol guessing is insufficient.
