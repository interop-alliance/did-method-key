# Plan: Convert `did-method-key` to TypeScript

Convert this project to TypeScript using the infrastructure from
`isomorphic-lib-template`, switch to the `@interop` forks, and drop BLS and
Ed25519VerificationKey2018 support.

## Decisions locked in

- **Rename** to `@interop/did-method-key`; update repo/homepage/bugs URLs.
- **Strip** the `Ed25519VerificationKey2018` branch + the `is2019`
  X25519-2019 derivation (and the `base58-universal` import) from the library.
  Library supports only 2020 / Multikey verification keys.
- **Keep** standalone `X25519KeyAgreementKey2019` *input* support (the
  `getKeyPair` detection + `addKeyAgreementKeyContext` X25519-2019 case) -- that
  is independent of 2018 and not in the drop list.
- **Tests:** port to Vitest (Node) AND add a Playwright browser spec exercising
  the driver.
- **Engine:** bump to node `>=24`, `packageManager: pnpm` (per template).

## Dependency changes (package.json rewrite from template)

**Runtime `dependencies`:**

- `@interop/did-io` (replaces `@digitalbazaar/did-io`) -- task 3
- `@interop/ed25519-verification-key` (replaces `@digitalbazaar/ed25519-multikey`) -- task 4
- `@digitalbazaar/x25519-key-agreement-key-2020` (keep -- used in `helpers.ts` KAK derivation)

`@interop/ed25519-verification-key` goes in runtime `dependencies` (mirroring the
original `ed25519-multikey` placement and the ed25519-default nature of
`did:key`), even though the driver core registers suites via `.use()` rather than
importing one.

**`devDependencies`:**

- `@digitalbazaar/ed25519-multikey` -- moved here, used for an interop cross-test -- task 5
- `@digitalbazaar/ecdsa-multikey` (keep -- Multikey tests)
- `@digitalbazaar/x25519-key-agreement-key-2019` (keep -- standalone 2019 KAK test)
- Template toolchain: `typescript`, `vitest`, `@vitest/coverage-v8`, `vite`,
  `@playwright/test`, `eslint`, `@eslint/js`, `typescript-eslint`,
  `eslint-config-prettier`, `globals`, `prettier`, `rimraf`, `@types/node`

**Dropped:**

- `@digitalbazaar/bls12-381-multikey` + its test (task 1)
- `@digitalbazaar/ed25519-verification-key-2018` + 2018 tests + 2018/2019-derivation lib code (task 2)
- `@digitalbazaar/ed25519-verification-key-2020` (tests now register
  `@interop/ed25519-verification-key`, which is the 2020 suite)
- Old toolchain: `c8`, `chai`, `cross-env`, `eslint-config-digitalbazaar`,
  `eslint-plugin-jsdoc`, `eslint-plugin-unicorn`, `karma*`, `mocha`,
  `mocha-lcov-reporter`, `webpack`

## File-level changes

**New infra (copied/adapted from `isomorphic-lib-template`):**

- `tsconfig.json`, `tsconfig.dev.json`, `eslint.config.js`, `prettier.config.js`,
  `vite.config.ts`, `playwright.config.ts`, `.editorconfig`, `test/index.html`,
  `CLAUDE.md`
- `src/declarations.d.ts` -- `declare module` shims for untyped packages:
  `@digitalbazaar/x25519-key-agreement-key-2020`,
  `@digitalbazaar/x25519-key-agreement-key-2019`,
  `@digitalbazaar/ecdsa-multikey`, `@digitalbazaar/ed25519-multikey`

**Source `lib/*.js` to `src/*.ts`:**

- `index.js` to `src/index.ts` (mechanical)
- `util.js` to `src/util.ts` (mechanical; add types to `createFromMultibase`)
- `helpers.ts` -- remove 2018 constants/branch, the `is2019` block, the
  `base58-universal` import, and the `@digitalbazaar/ed25519-multikey` import (no
  longer used after stripping). Add types: `DidDocument`, a light
  `KeyPairLike`/`VerificationMethod` interface, options objects.
- `DidKeyDriver.ts` -- add types: `_allowedKeyTypes: Map<string, FromMultibase>`,
  typed method signatures/options, return types.

**Tests:**

- `test/node/driver.test.ts` -- port `driver.spec.js` from Mocha/chai to Vitest
  (`describe/it/expect`), dropping the BLS test and the three 2018-mode tests;
  switch the ed25519 suite to `@interop/ed25519-verification-key`. Add one interop
  test: key generated via `@digitalbazaar/ed25519-multikey` resolves to the same
  DID doc through `@interop/ed25519-verification-key` (task 5).
- `test/browser/driver.spec.ts` -- Playwright spec importing the driver via
  `/src/index.ts`, running a representative resolve + `fromKeyPair` round-trip in
  Chromium.
- Delete `test/driver.spec.js`, `test/.eslintrc.cjs`, `.eslintrc.cjs`,
  `karma.conf.cjs`.

**Other:**

- `package.json` -- full rewrite (name, scripts, exports, files, type, engines
  `>=24`, `packageManager: pnpm`, build via `tsc`).
- `.gitignore` -- add `dist`, `node_modules`, `playwright-report`, `test-results`.
- `README.md` -- update install/import examples to `@interop/*` packages; remove
  the 2018-mode section.
- `CHANGELOG.md` -- add a major-version entry noting TS conversion, scope rename,
  dropped BLS/2018 support, fork switches.
- `.github/` workflow -- update CI to pnpm + new
  `lint`/`test-node`/`test-browser`/`build` scripts.

## Typing approach

Pragmatic. `strict: true` + `noUncheckedIndexedAccess` are on, but
`@typescript-eslint/no-explicit-any` is off in the template -- so define real
interfaces for DID documents, verification methods, and driver options, and fall
back to `any` for the dynamic registered-suite key-pair objects rather than
over-modeling third-party suites.

## Verification

1. `pnpm install`
2. `pnpm run lint`
3. `pnpm run build` (clean `tsc` to `dist/`)
4. `pnpm run test-node` (Vitest)
5. `pnpm run test-browser` (Playwright/Chromium)

## Open risk to confirm during implementation

The forks resolve via `moduleResolution: Bundler` to source. Confirm
`@interop/ed25519-verification-key`'s
`Ed25519VerificationKey.from`/`.generate`/`.export({publicKey, includeContext})`/`.fingerprint()`
match the exact shapes the driver expects so the ported assertions (contexts, key
IDs) pass unchanged. If the fork's `export()` output differs (e.g. `@context`
handling), adjust the assertions or note the behavior change rather than silently
loosening tests.
