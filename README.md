# did:key method driver _(@interop/did-method-key)_

[![CI](https://github.com/interop-alliance/did-method-key/workflows/CI/badge.svg)](https://github.com/interop-alliance/did-method-key/actions?query=workflow%3ACI)
[![NPM Version](https://img.shields.io/npm/v/@interop/did-method-key)](https://www.npmjs.com/package/@interop/did-method-key)

> A [DID](https://w3c.github.io/did-core) (Decentralized Identifier) method driver for the `did-io` library and for standalone use

## Table of Contents

- [Background](#background)
  * [Example DID Document](#example-did-document)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Background

See also (related specs):

* [Decentralized Identifiers (DIDs)](https://w3c.github.io/did-core)
* [Linked Data Cryptographic Suite Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry/)
* [Linked Data Proofs](https://w3c-dvcg.github.io/ld-proofs/)

A `did:key` method driver for the [`@interop/did-io`](https://github.com/interop-alliance/did-io)
client library and for standalone use.

The `did:key` method is used to express public keys in a way that doesn't
require a DID Registry of any kind. Its general format is:

```
did:key:<multibase encoded, multicodec identified, public key>
```

So, for example, the following DID would be derived from a multibase encoded
ed25519 public key:

```
did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
```

That DID would correspond to the following DID Document:

### Example DID Document

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
  "verificationMethod": [
    {
      "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
      "type": "Multikey",
      "controller": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
      "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
    }
  ],
  "authentication": [
    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
  ],
  "assertionMethod": [
    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
  ],
  "capabilityDelegation": [
    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
  ],
  "capabilityInvocation": [
    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
  ]
}
```

## Security

By default this driver represents verification keys as W3C
[`Multikey`](https://www.w3.org/TR/cid-1.0/#Multikey) verification methods, and
does not derive a separate `keyAgreement` (X25519) key.

If you register a verification suite that exports the legacy
`Ed25519VerificationKey2020` shape, the driver will additionally derive a
Curve25519 `keyAgreement` public key (suitable for Diffie-Hellman key exchange)
from the source Ed25519 key, using
[`ed2curve-js`](https://github.com/dchest/ed2curve-js). Note that this derived
key is optional -- there's at least
[one proof](https://eprint.iacr.org/2021/509) that this is safe to do.

## Install

Requires Node.js 24+.

To install from `npm`:

```
npm install --save @interop/did-method-key
```

To install locally (for development), this project uses
[`pnpm`](https://pnpm.io):

```
git clone https://github.com/interop-alliance/did-method-key.git
cd did-method-key
pnpm install
```

## Usage

### `use()`

This method registers a multibase-multikey header and a multibase-multikey
deserializer and configures a driver to use a multibase-multikey deserializer
to handle data using that multibase-multikey header.

```js
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey'
import { driver } from '@interop/did-method-key'

const didKeyDriverMultikey = driver()

didKeyDriverMultikey.use({
  multibaseMultikeyHeader: 'zDna',
  fromMultibase: EcdsaMultikey.from
})
```

### `createFromMultibase()`

This utility function adapts a verification suite that exposes a
`fromFingerprint()` static method (rather than a `fromMultibase()` method) so
that it works with `DidKeyDriver`.

```js
import { driver, createFromMultibase } from '@interop/did-method-key'
import { SomeVerificationKey } from 'some-verification-suite'

const didKeyDriver = driver()

didKeyDriver.use({
  multibaseMultikeyHeader: header,
  fromMultibase: createFromMultibase(SomeVerificationKey)
})
```

### `fromKeyPair()`

To generate a new key and get its corresponding `did:key` method DID Document
from a verification keypair.

```js
import { driver } from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

const didKeyDriver = driver()

didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey.from
})

const publicKeyMultibase = 'z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
const verificationKeyPair = await Ed25519VerificationKey.from({
  publicKeyMultibase
})
// or perhaps:
// const verificationKeyPair = await Ed25519VerificationKey.generate();

const { didDocument, keyPairs, methodFor } = await didKeyDriver.fromKeyPair({
  verificationKeyPair
})

// print the DID Document above
console.log(JSON.stringify(didDocument, null, 2))

// keyPairs will be set like so =>
Map(1) {
  'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T#z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T' => Ed25519VerificationKey {
    id: 'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T#z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T',
    controller: 'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T',
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: 'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
  }
}
```

`methodFor` is a convenience function that returns a key pair instance that
contains `publicKeyMultibase` for a given purpose. For example, a verification
key (containing `signer()` and `verifier()` functions) is frequently useful for
[`jsonld-signatures`](https://github.com/digitalbazaar/jsonld-signatures)
operations. After generating a new did:key DID, you can do:

```js
// For signing Verifiable Credentials
const assertionKeyPair = methodFor({ purpose: 'assertionMethod' })
// For Authorization Capabilities (zCaps)
const invocationKeyPair = methodFor({ purpose: 'capabilityInvocation' })
```

Note that `methodFor` returns a key pair that contains a `publicKeyMultibase`.
This makes it useful for _verifying_ and _encrypting_ operations.

Because the default `Multikey` representation does not derive a `keyAgreement`
key, `methodFor({ purpose: 'keyAgreement' })` will throw for an ed25519 DID
unless you explicitly supplied a `keyAgreementKeyPair` to `fromKeyPair()`.

### `publicKeyToDidDoc()`

If you already have a public key object (as an LDKeyPair instance, or a plain
key description object), you can turn it into a DID Document:

```js
const { didDocument } = await didKeyDriver.publicKeyToDidDoc({
  publicKeyDescription
})
```

### `get()`

#### Getting a full DID Document from a `did:key` DID

To get a DID Document for an existing `did:key` DID:

```js
const did = 'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
const didDocument = await didKeyDriver.get({ did })
```

(Results in the [example DID Doc](#example-did-document) above).

#### Getting the DID Document from key id

You can also use a `.get()` to retrieve an individual key, if you know its id
already (this is useful for constructing `documentLoader`s for JSON-LD Signature
libs, and the resulting key does include the appropriate `@context`).

```js
const verificationKeyId =
  'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T#z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'

const keyData = await didKeyDriver.get({ url: verificationKeyId })

// key node ->
console.log(JSON.stringify(keyData, null, 2))
```

### `publicMethodFor()`

Often, you have just a `did:key` DID, and you need to get a key for a
particular _purpose_ from it, such as an `assertionMethod` key to verify a
VC signature.

For that purpose, you can use a combination of `get()` and `publicMethodFor`:

```js
// Start with the DID
const didDocument = await didKeyDriver.get({ did })
// This lets you use `publicMethodFor()` to get a key for a specific purpose
const assertionMethod = didKeyDriver.publicMethodFor({
  didDocument,
  purpose: 'assertionMethod'
})

// If you have a known key type, you can create a key instance which gives you
// access to a `verify()` function.
const assertionMethodPublicKey =
  await Ed25519VerificationKey.from(assertionMethod)
const { verify } = assertionMethodPublicKey.verifier()
```

`publicMethodFor` will throw an error if no key is found for a given purpose.

## Contribute

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[New BSD License (3-clause)](LICENSE) © Interop Alliance and Digital Bazaar
