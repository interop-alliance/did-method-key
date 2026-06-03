# @interop/did-method-key ChangeLog

## 7.1.1 -

### Fixed
- Add default export to `package.json`.

## 7.1.0 - 2026-06-01

### Changed
- `DidKeyDriver` now `implements` the `DidMethodDriver` interface from
  `@interop/did-io` (`^4.0.1`). The `generate()` and `fromKeyPair()` return
  types are declared as did-io's `DidGenerationResult`; `get()` accepts
  `did?: IDID | string`, `publicKeyToDidDoc()` accepts an `IPublicKey`
  `publicKeyDescription`, and `fromKeyPair()`/`generate()` type their
  `keyAgreementKeyPair` as `AbstractKeyPair | IKeyPair` (matching the
  interface) rather than `any`.

## 7.0.0 - 2026-06-01

### Changed
- **BREAKING**: Swap dependencies to `@interop/data-integrity-core`, dropping
  `@digitalcredentials/ssi` and `@digitalcredentials/keypair` (both now folded
  into `data-integrity-core`). The `KeyPair` abstract class is renamed to
  `AbstractKeyPair`; the `IDidDocument` / `IPublicKey` / `IKeyPair` / `IDID`
  types are now imported from `@interop/data-integrity-core`, and the former
  `IKeyIdOrObject` is now `IVerificationMethodEntry`. Mirrors
  `@interop/ed25519-verification-key@7.0.0` and `@interop/did-io@4.0.0`.
- **BREAKING**: Require `@interop/did-io` `^4.0.0` and
  `@interop/ed25519-verification-key` `^7.0.0`.
- Verification key-pair instances, the `keyPairs` map
  (`Map<string, AbstractKeyPair>`), and `methodFor()` / `computeId()` are now
  typed with `AbstractKeyPair`; instance-or-description inputs are typed
  `AbstractKeyPair | IKeyPair`. The X25519 key-agreement path
  (`@digitalbazaar/x25519-key-agreement-key-2020`) remains `any`.
- Accommodate stricter `data-integrity-core` DID-document types: a suite's
  exported `@context` may be `string | string[]` (spread into the document
  contexts), and the exported public key is cast to `IVerificationMethod` when
  placed into `verificationMethod`.

### Removed
- **BREAKING**: No longer re-export `data-integrity-core` types from the package
  entrypoint -- the previously re-exported `KeyPair` (now `AbstractKeyPair`),
  `IDidDocument`, and `IPublicKey` are gone. Import them directly from
  `@interop/data-integrity-core`. The package's own `FromMultibase` and
  `KeyPairClass` types are still exported.

## 6.2.0-6.2.1 - 2026-05-27

### Changed
- **BREAKING**: Replaced the `any`-typed key-pair instances with concrete types.
  Verification key-pair instances and the `keyPairs` map are now typed as
  `@digitalcredentials/keypair`'s `KeyPair` class, and the local `DidDocument` /
  `VerificationMethod` interfaces were dropped in favor of ssi's `IDidDocument` /
  `IPublicKey`. Instance-or-description inputs to `fromKeyPair()` are typed
  `KeyPair | IKeyPair`, discriminated at runtime via an `'export' in keyPair`
  check (a live instance vs. a serialized KMS description).
- The lone remaining `any` is the X25519 key-agreement path
  (`@digitalbazaar/x25519-key-agreement-key-2020`): it is a key-*agreement* key
  with no `signer()` / `verifier()`, so it does not structurally satisfy
  `KeyPair`. This will be tightened if that suite extends `KeyPair` and ships
  ssi types.

## 6.1.0 - 2026-05-27

### Added
- Add `use({ keyPairClass })` form. Registering a KeyPair suite class lets the
  driver read the multibase-multikey header, deserializer, and key generator off
  the class, so callers no longer have to know or hard-code the literal
  multibase prefix. Requires a suite that exposes a static `multibaseHeader`
  (e.g. `@interop/ed25519-verification-key` v6.2.0+). The lower-level
  `use({ multibaseMultikeyHeader, fromMultibase })` form is retained for suites
  without that contract (resolution only).
- Add `generate({ keyType, seed, keyAgreementKeyPair })`, which generates a new
  key pair using a registered suite and returns its DID Document. When exactly
  one suite is registered it is used automatically; when several are registered,
  `keyType` (a KeyPair class or its multibase header) selects which. An optional
  `seed` (`Uint8Array`) is passed through to the registered suite's `generate()`
  to deterministically derive the key pair; when omitted, the suite generates a
  random key pair. This also restores compatibility with `@interop/did-io`'s
  `CachedResolver.generate()` pass-through. `generate()` requires a suite
  registered via `use({ keyPairClass })`.
- Export the `KeyPairClass` type.

### Changed
- `fromKeyPair()` and `generate()` no longer require a prior `use()` call: a
  live key pair instance is now used directly. The `use()` registry is still
  consulted to rebuild a key from a plain key description (e.g. from a KMS) in
  `publicKeyToDidDoc()`, and to deserialize keys during `get()` resolution.

## 6.0.0-6.0.1 - 2026-05-27

### Changed
- **BREAKING**: Forked to `@interop/did-method-key` and converted to TypeScript.
  The package is now built with `tsc` to `dist/`, ships type declarations, and
  uses `pnpm`. Requires Node.js 24+.
- **BREAKING**: Switched from `@digitalbazaar/did-io` to `@interop/did-io`, and
  from `@digitalbazaar/ed25519-multikey` to `@interop/ed25519-verification-key`.
- Tests migrated from Mocha/Karma to Vitest (Node) and Playwright (browser).

### Removed
- **BREAKING**: Dropped support for BLS12-381 keys and the
  `Ed25519VerificationKey2018` / legacy `X25519KeyAgreementKey2019`-derivation
  code paths (and their tests).

## 5.3.0 - 2025-09-21

### Changed
- Update dependencies to remove legacy 2019 x25519 library.

## 5.2.0 - 2024-01-17

### Added
- Allow `fromKeyPair` to be called with only a key agreement key pair.

## 5.1.0 - 2023-04-27

### Changed
- Update `get()` and `publicKeyToDidDoc()` to support `keyAgreement-only` DIDs.

## 5.0.0 - 2023-04-11

### Added
- Add `use()` method that allows multibase-multikey headers and a
  multibase-multikey deserializer (which replaces `verificationSuite`
  previously) to handle data using that header.
- Add `fromKeyPair()` that generates the DID Document along with the
  corresponding key pairs from a `verificationKeyPair`. `fromKeyPair()` also
  optionally takes a `keyAgreementKeypair` param.

### Changed
- **BREAKING** Renamed `createVerificationSuite()` to `createFromMultibase()`
  which now no longer takes a `generate` param and is adapted to convert the
  legacy verification suites to provide proper `.fromMultibase()` method.

### Removed
- **BREAKING**: `DidKeyDriver` no longer takes a `verificationSuite` param in
  the constructor.
- **BREAKING**: `generate()` method has now been replaced by a new method
  `fromKeyPair()`. This approach externalizes key pair generation to allow
  whatever parameters are necessary / possible (such as random bytes / seeds)
  to be provided in the key-pair-specific implementation. This also greatly
  reduces the complexity of this library and the need to import key pair
  libraries generally.

## 4.0.0 - 2023-04-03

### Added
- Added ECDSA Multikey support. Exports `createVerificationSuite()` utility
  function that can be used to create a `verificationSuite` from a multikey
  library such as `@digitalbazaar/ecdsa-multikey` when creating a
  `DidKeyDriver` instance.

### Changed
- **BREAKING**: Remove support for node <= 14.

## 3.0.0 - 2022-06-02

### Changed
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Require Node.js >=14.
- Update dependencies.
- Lint module.

## 2.0.0 - 2021-06-19

### Changed
- **BREAKING**: Update 2020 cryptosuites to use multicodec encoding for keys.

## 1.2.0 - 2021-05-26

### Added
- Add backwards compatibility, allow returning the `did:key` document using
  the `Ed25519VerificationKey2018` and `X25519KeyAgreementKey2019` suites.

## 1.1.0 - 2021-05-04

### Added
- Add `didKeyDriver.publicKeyToDidDoc({keyPair})` method. (This used to be
  the `keyToDidDoc()` method, in `<= v0.7.0`, removed in v1.0 and brought back
  by popular demand.)

## 1.0.0 - 2021-04-09

### Changed
- **BREAKING**: Rename npm package from `did-method-key` to
  `@digitalbazaar/did-method-key`.
- **BREAKING**: Return `{didDocument, keyPairs, methodFor}` from `generate()`.
- **BREAKING**: Upgrade to `crypto-ld` v5.0 based key suites, update to use
  `Ed25519VerificationKey2020` and `X25519KeyAgreementKey2020` crypto suites.
- **BREAKING**: DID Document context changed from `'https://w3id.org/did/v0.11'`
  to the DID WG-published `https://www.w3.org/ns/did/v1`, plus the contexts
  for the `Ed25519VerificationKey2020` and `X25519KeyAgreementKey2020` crypto
  suites. See the "Example DID Document" section of the README.
- **BREAKING**: Rename `computeKeyId()` -> `computeId()`.
- Avoid mutation of ed25519 key passed into keyToDidDoc.
- Use underscores for utility functions.
- Add `methodFor` and `publicMethodFor` convenience functions.
- **BREAKING**: Move the lru-cache to `did-io`'s `CachedResolver` class.
- **BREAKING**: `keyToDidDoc` driver method removed. (See Upgrading notes
  for alternatives.)
- **BREAKING**: The `publicKey` property of the DID Document has been deprecated
  by the DID Data Model, and is now renamed to `verificationMethod`.

### Upgrading from <= v.0.7.0

**1)** Check for the changed `generate()` return signature. The usage is now:

```js
const {didDocument, keyPairs, methodFor} = await didKeyDriver.generate();
```

Note that `keyPairs` is a js `Map` instance containing the public/private key
pairs for both the signing key and the X25519 key agreement key.

And the `methodFor` convenience function allows you to fetch a particular
public/private key pair for a given purpose. For example:

```js
const {didDocument, keyPairs, methodFor} = await didKeyDriver.generate();
const authenticationKeyPair = methodFor({purpose: 'authentication'});
const keyAgreementKeyPair = methodFor({purpose: 'keyAgreement'});
```

**2)** Make sure to adjust your `documentLoader` to handle the new contexts.

**3)** The `keyToDidDoc` function has been renamed to `publicKeyToDidDoc()` (as
of v1.1), and the return signature has changed.

```js
// For example, if you have a key description object (such as that returned by
// a KMS system's "generate key" operation):
const publicKeyDescription = {
  "@context": "https://w3id.org/security/suites/ed25519-2020/v1",
  "id": "did:key:z6MkuBLrjSGt1PPADAvuv6rmvj4FfSAfffJotC6K8ZEorYmv#z6MkuBLrjSGt1PPADAvuv6rmvj4FfSAfffJotC6K8ZEorYmv",
  "type": "Ed25519VerificationKey2020",
  "controller": "did:key:z6MkuBLrjSGt1PPADAvuv6rmvj4FfSAfffJotC6K8ZEorYmv",
  "publicKeyMultibase": "zFj5p9C2Sfqth6g6DEXtw5dWFqrtpFn4TCBBPJHGnwKzY"
};
const {didDocument} = await didKeyDriver.publicKeyToDidDoc({publicKeyDescription});

// Or, you can start with an `LDKeyPair` instance:
const keyPair = await Ed25529VerificationKey2020.generate();
const {didDocument} = await didKeyDriver.publicKeyToDidDoc({publicKeyDescription: keyPair});
```

Don't forget that you can use the `didKeyDriver.publicMethodFor({purpose})`
method to fetch a particular key, after creating the DID Document.

```js
const keyAgreementKey = didKeyDriver.publicMethodFor({didDocument, purpose: 'keyAgreement'});
// Note that the resulting keyAgreementKey pair will only have the public key material, not private
```

## 0.7.0 - 2020-09-23

### Added
- Add cache with option to configure its max size.

### Changed
- **BREAKING**: Make `keyToDidDoc` asynchronous.

## 0.6.1 - 2020-04-20

### Changed
- Return public/private key pair from `generate()`, available on `didDoc.keys`.

## 0.6.0 - 2020-04-13

### Changed
- **BREAKING**: Use `x25519-key-pair` v2.0.0, changed fingerprint format
  for X25519 keys.
- Use `crypto-ld` v0.3.7.

### Added
- Add `computeKeyId()` and `method` to driver, to work with `did-io` downstream.

## 0.5.1 - 2020-02-27

### Changed
- Use x25519-key-pair@1.

## 0.5.0 - 2020-02-24

### Added
- `driver.get()` can now also resolve individual keys.

### Changed
- **BREAKING**: Undo previous change, using `https://w3id.org/did/v0.11` as
  `@context`, apologies for the confusion.

## 0.4.0 - 2020-01-29

### Changed
- **BREAKING**: Now using `'https://www.w3.org/ns/did/v1'` as context.

## 0.3.0 - 2020-01-08

### Changed
- **BREAKING**: Fix - Use fingerprint hash fragment as key id.

## 0.2.0 - 2019-08-22

### Added
- Add core files.

- See git history for changes previous to this release.
