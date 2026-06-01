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
}
