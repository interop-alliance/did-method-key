# Agent Guidelines

## Current Project

- A `did:key` method driver, forked from `@digitalbazaar/did-method-key` to
  `@interop/did-method-key`.
- TypeScript, built with `tsc`; tested with Vitest (Node) and Playwright (browser).
- Supports Ed25519VerificationKey2020 / Multikey verification keys and
  X25519KeyAgreementKey2019/2020 key agreement keys. BLS and
  Ed25519VerificationKey2018 are not supported.

## Architecture

### The driver is suite-agnostic

`DidKeyDriver` does not import any verification suite. Callers register suites at
runtime via `use({ multibaseMultikeyHeader, fromMultibase })`, which maps a
4-character multibase prefix (e.g. `z6Mk` for ed25519, `zDna` for ecdsa, `z6LS`
for x25519) to a `fromMultibase` deserializer. Resolution (`get()`) reads the
prefix off the DID, looks up the registered deserializer, and fails with
"Unsupported multibaseMultikeyHeader" if none is registered. This means the
package has no opinion about key types beyond what the consumer wires up; the
suite's own `.export()` output determines the verification method `type` and
`@context` that land in the DID document.

### Output representation follows the registered suite's `export()`

`_keyPairToDidDocument()` (the core of the library) calls
`keyPair.export({ publicKey: true, includeContext: true })` and uses the
resulting `type` to decide context and key-agreement derivation. Consequence:
the *same* ed25519 key produces different DID documents depending on the
registered suite.

- `@interop/ed25519-verification-key` (`Ed25519VerificationKey`) exports
  **Multikey** by default, so ed25519 DIDs resolve to a `Multikey`
  verification method with context `[did/v1, multikey/v1]` and **no** derived
  X25519 keyAgreement (the `Multikey` branch in `getKeyAgreementKeyPair` is a
  deliberate no-op/FIXME). This is the representation the tests and README
  assume.
- A suite that exports `Ed25519VerificationKey2020` (the legacy shape) would
  instead trigger `X25519KeyAgreementKey2020.fromEd25519(...)`
  and add a derived keyAgreement key. The 2020 branch is retained for that case
  but is not exercised by the default suite.

If you change which suite the README/tests register, re-derive the expected
contexts, verification-method `type`, and presence/absence of `keyAgreement`.

### Source modules (`src/`)

- `index.ts` — public entrypoint: `driver()` factory, `DidKeyDriver`,
  `createFromMultibase`, and re-exported types.
- `DidKeyDriver.ts` — the driver class: `use`, `get`, `fromKeyPair`,
  `publicKeyToDidDoc`, `publicMethodFor`, `computeId`, and the private
  `_keyPairToDidDocument`.
- `helpers.ts` — pure helpers for DID/key-id construction, context assembly,
  key-agreement derivation, and the multibase header lookup. This is the only
  module that imports a concrete suite
  (`@interop/x25519-key-agreement-key`, for KAK derivation).
- `util.ts` — `createFromMultibase`, an adapter that wraps a suite exposing a
  static `fromFingerprint()` so it satisfies the `fromMultibase` contract.
- `types.ts` — shared `DidDocument`, `VerificationMethod`, and `FromMultibase`
  types. Key-pair instances are intentionally typed `any` (suites are dynamic
  and duck-typed); `@typescript-eslint/no-explicit-any` is disabled to allow this.
- `declarations.d.ts` — ambient `declare module` shims for untyped
  `@digitalbazaar/*` packages.

### keyAgreement-only DIDs

`get()` and `publicKeyToDidDoc()` accept a bare X25519 key agreement key (prefix
`z6LS`). In that path `getKeyPair()` returns `{ keyPair: null, keyAgreementKeyPair }`
and `_keyPairToDidDocument()` builds a document with only a `keyAgreement`
relationship (no verificationMethod / authentication / assertionMethod).

### Dependency boundaries

- Runtime: `@interop/did-io` (only for `findVerificationMethod` in
  `publicMethodFor`; it also supplies the `DidMethodDriver` interface that
  `DidKeyDriver` implements and the `DidGenerationResult` return type, both
  type-only imports), `@interop/ed25519-verification-key`, and
  `@interop/x25519-key-agreement-key`.
  `@interop/data-integrity-core` is a runtime dependency too, but used only for
  type imports (`AbstractKeyPair`, `IDidDocument`, `IPublicKey`, `IKeyPair`,
  `IVerificationMethod`, `IVerificationMethodEntry`, `IDID`); it contributes no
  runtime code.
- `@digitalbazaar/ed25519-multikey` is a **devDependency**, used only by the
  interop test that asserts the digitalbazaar and `@interop` ed25519 suites
  resolve byte-identical DID documents.

## To-Do / Follow-ups

- **Key-pair typing -- mostly done.** The verification key-pair instances and
  the `keyPairs` map are now typed as `@interop/data-integrity-core`'s
  `AbstractKeyPair` class; the local `DidDocument` / `VerificationMethod`
  interfaces were dropped in favor of data-integrity-core's `IDidDocument` /
  `IPublicKey`. Instance-or-description inputs are typed
  `AbstractKeyPair | IKeyPair` (the `'export' in keyPair` runtime check
  discriminates a live instance from a serialized KMS description).

  The lone remaining `any` is the **x25519 key-agreement path** in
  `helpers.ts` / `_keyPairToDidDocument`. The suite itself
  (`@interop/x25519-key-agreement-key`) now ships types and extends
  `AbstractKeyPair`, so the `declarations.d.ts` shim is gone; the remaining
  `any` annotations on `keyAgreementKeyPair` can be tightened to
  `X25519KeyAgreementKey2020 | AbstractKeyPair` in a follow-up.

  Note also that data-integrity-core's DID-document types are stricter than the
  old `ssi` ones: a suite's exported `@context` is `string | string[]` (so
  `_keyPairToDidDocument` spreads it into `contexts`), and DID-document
  verification-relationship fields hold `IVerificationMethodEntry`, so the
  exported public key is cast to `IVerificationMethod` when placed into
  `verificationMethod`.

- **`did-io` container reconciliation -- done (did-io v4.0.0).** did-io's
  `IKeyMap` is now `Map<string, AbstractKeyPair>` (was
  `Record<string, IKeyPair>`), matching the `keyPairs` map this package returns;
  its `DidGenerationResult`
  (`{ didDocument: IDidDocument, keyPairs: IKeyMap, methodFor: (...) => AbstractKeyPair }`)
  lines up with this driver's `fromKeyPair()` / `generate()` return types. did-io
  now depends on `@interop/data-integrity-core` for the concrete
  `AbstractKeyPair` type. This package requires `@interop/did-io` `^4.0.0`. The
  sibling `did-web-resolver` driver still needs the same audit.

## Toolchain & Project Layout

### Package Manager

Use `pnpm` (not `npm` or `yarn`). The lockfile is `pnpm-lock.yaml`. Install deps
with `pnpm install`; run scripts with `pnpm run <script>` or `pnpm <script>`.

### Build

The library is built with `tsc` (not `vite build`). `vite.config.ts` exists only
to configure Vitest and to run `vite dev` as a server for Playwright. Running
`pnpm run build` compiles `src/` to `dist/` via `tsconfig.json`.

### Two tsconfigs

- `tsconfig.json` — library build only; includes `src/**/*`
- `tsconfig.dev.json` — extends the above with `noEmit: true`; adds `test/**/*`, `vite.config.ts`, and
  `playwright.config.ts` so ESLint's type-aware rules cover all files

Do not add test files to `tsconfig.json` — they would be emitted into `dist/`.

### Tests

- `test/node/` — Vitest unit tests (`pnpm run test-node`); run in Node
- `test/browser/` — Playwright tests (`pnpm run test-browser`); run in real
  Chromium via a Vite dev server (`pnpm run dev`)

The `dev` script exists solely to give Playwright a server that can serve and
transform TypeScript source files on the fly. There is no browser app.

### ESM & import paths

The package is ESM-only (`"type": "module"`). Local imports must use the `.js`
extension even though source files are `.ts` — e.g.
`import { Example } from '../../src/index.js'`. TypeScript's `moduleResolution: Bundler`
resolves these to the `.ts` source at compile time.

## Conventions

Code style, refactoring, JSDoc, comment, and error-handling conventions live in @CONTRIBUTING.md -- follow them.
