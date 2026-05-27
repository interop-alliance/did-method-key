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
