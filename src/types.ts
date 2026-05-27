/*!
 * Copyright (c) 2021-2026 Digital Bazaar, Inc. All rights reserved.
 */

/**
 * A verification method (public key) node within a DID Document.
 */
export interface VerificationMethod {
  id: string
  type: string
  controller: string
  publicKeyMultibase?: string
  publicKeyBase58?: string
  '@context'?: string | string[]
}

/**
 * A `did:key` method DID Document.
 */
export interface DidDocument {
  '@context': string[]
  id: string
  verificationMethod?: VerificationMethod[]
  authentication?: string[]
  assertionMethod?: string[]
  capabilityDelegation?: string[]
  capabilityInvocation?: string[]
  keyAgreement?: VerificationMethod[]
}

/**
 * A multibase-multikey deserializer: converts a `{publicKeyMultibase}` value
 * into a key pair interface.
 */
export type FromMultibase = (options: {
  publicKeyMultibase: string
}) => Promise<any>

/**
 * A KeyPair suite class usable for `did:key` generation and resolution via
 * `DidKeyDriver.use({ keyPairClass })`. The static `multibaseHeader` (the
 * 4-character multibase-multikey prefix, e.g. `z6Mk` for ed25519) lets the
 * driver register the suite without the caller having to know that prefix.
 */
export interface KeyPairClass {
  multibaseHeader: string
  from: FromMultibase
  generate?: (options?: object) => Promise<any>
}

/**
 * An entry in the driver's registry of allowed key types, keyed by
 * multibase-multikey header.
 */
export interface RegisteredKeyType {
  fromMultibase: FromMultibase
  generate?: (options?: object) => Promise<any>
}
