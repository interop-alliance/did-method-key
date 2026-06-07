/*!
 * Copyright (c) 2021-2026 Digital Bazaar, Inc. All rights reserved.
 */
import type { AbstractKeyPair } from '@interop/data-integrity-core'

/**
 * A multibase-multikey deserializer: converts a `{publicKeyMultibase}` value
 * into a live key pair instance.
 */
export type FromMultibase = (options: {
  publicKeyMultibase: string
}) => Promise<AbstractKeyPair>

/**
 * A KeyPair suite class usable for `did:key` generation and resolution via
 * `DidKeyDriver.use({ keyPairClass })`. The static `multibaseHeader` (the
 * 4-character multibase-multikey prefix, e.g. `z6Mk` for ed25519) lets the
 * driver register the suite without the caller having to know that prefix.
 */
export interface KeyPairClass {
  multibaseHeader: string
  from: FromMultibase
  generate?: (options?: object) => Promise<AbstractKeyPair>
}

/**
 * An entry in the driver's registry of allowed key types, keyed by
 * multibase-multikey header.
 */
export interface RegisteredKeyType {
  fromMultibase: FromMultibase
  generate?: (options?: object) => Promise<AbstractKeyPair>
  /**
   * When `true`, resolving a `did:key` for this key type also derives an
   * X25519 keyAgreement key from the (Ed25519) verification key and adds it to
   * the DID document. Off by default; only meaningful for Ed25519 (`z6Mk`)
   * registrations. See `DidKeyDriver.use()`.
   */
  enableEncryptionKeyDerivation?: boolean
}
