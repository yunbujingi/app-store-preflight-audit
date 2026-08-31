# Target graph evidence

Use target graph inspection before attributing a source signal, manifest, entitlement, or dependency to a shipped product. Repository-wide matches without target membership are leads, not target-specific findings.

## Evidence order

1. Parse `PBXSourcesBuildPhase`, `PBXResourcesBuildPhase`, and `PBXFileSystemSynchronizedRootGroup` membership without executing project code. Synchronized-group exception sets remain unresolved unless Xcode-resolved metadata confirms them.
2. When explicitly enabled, collect `xcodebuild -list -json` and `xcodebuild -showBuildSettings -json` with automatic package resolution disabled.
3. Normalize only decision-relevant settings: `PRODUCT_BUNDLE_IDENTIFIER`, `WRAPPER_EXTENSION`, `MACH_O_TYPE`, `SUPPORTED_PLATFORMS`, `CONFIGURATION`, `TARGET_BUILD_DIR`, `EXECUTABLE_PATH`, product name, Info.plist path, SDK/platform, architectures, and configuration-specific include/exclude patterns.
4. Parse workspace project references, local SwiftPM product/target/plugin declarations, generated build-phase outputs, and relevant XCConfig includes/conditional assignments. Treat unresolved macros or conditions as unresolved evidence.
5. Import Link Maps only when supplied. Attribute each static-library member and symbol to the final executable and target candidate without preserving absolute linker paths.
6. Prefer Archive evidence over build settings for the submitted artifact.

The stable relation is:

```text
source/resource → target → configuration → product → bundle ID → executable → manifest
```

Keep absolute build roots tokenized. A generated output declaration proves that a build phase claims the path, not that the file was produced or compiled. XCConfig `sdk[...]`, `config[...]`, and platform filters are evaluated only when matching build-setting context is available; all other conditions remain unresolved.

Static library source ownership can be established from target membership. Attribution of code already linked into a final executable requires a Link Map or equivalent linker evidence; filename or symbol guessing is insufficient.
