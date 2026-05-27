/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020'
import type { KeyPair } from '@digitalcredentials/keypair'
import type {
  IDID,
  IDidDocument,
  IKeyIdOrObject,
  IKeyPair,
  IPublicKey
} from '@digitalcredentials/ssi'
import type { FromMultibase } from './types.js'

/**
 * Normalizes a DID Document verification-relationship value (which the data
 * model permits to be a single entry or an array) to an array.
 */
function toArray(
  value?: IKeyIdOrObject | IKeyIdOrObject[]
): IKeyIdOrObject[] {
  if (value == null) {
    return []
  }
  return Array.isArray(value) ? value : [value]
}

const ED25519_KEY_2020_TYPE = 'Ed25519VerificationKey2020'
const ED25519_KEY_2020_CONTEXT_URL =
  'https://w3id.org/security/suites/ed25519-2020/v1'

const MULTIKEY_TYPE = 'Multikey'
const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1'

const X25519_2019_TYPE = 'X25519KeyAgreementKey2019'
const X25519_2019_CONTEXT_URL =
  'https://w3id.org/security/suites/x25519-2019/v1'

const X25519_2020_TYPE = 'X25519KeyAgreementKey2020'
const X25519_2020_CONTEXT_URL =
  'https://w3id.org/security/suites/x25519-2020/v1'

const contextsBySuite = new Map<string, string>([
  [ED25519_KEY_2020_TYPE, ED25519_KEY_2020_CONTEXT_URL],
  [MULTIKEY_TYPE, MULTIKEY_CONTEXT_V1_URL],
  [X25519_2020_TYPE, X25519_2020_CONTEXT_URL],
  [X25519_2019_TYPE, X25519_2019_CONTEXT_URL]
])

/**
 * Returns the public key object for a given key id fragment.
 *
 * @param options {object} - Options hashmap.
 * @param options.didDocument {IDidDocument} - The DID Document to use when
 *   generating the id.
 * @param options.keyIdFragment {string} - The key identifier fragment.
 *
 * @returns {IPublicKey} Returns the public key node, with `@context`.
 */
export function getKey({
  didDocument,
  keyIdFragment
}: {
  didDocument: IDidDocument
  keyIdFragment: string
}): IPublicKey {
  // Determine if the key id fragment belongs to the "main" public key,
  // or the keyAgreement key
  const keyId = didDocument.id + '#' + keyIdFragment
  const [verificationMethod] = toArray(didDocument.verificationMethod)
  let publicKey: IPublicKey
  if (
    typeof verificationMethod === 'object' &&
    verificationMethod.id === keyId
  ) {
    // Return the public key node for the main public key
    publicKey = verificationMethod
  } else {
    // Return the public key node for the X25519 key-agreement key
    publicKey = toArray(didDocument.keyAgreement)[0] as IPublicKey
  }

  return {
    '@context': publicKey.type
      ? contextsBySuite.get(publicKey.type)
      : undefined,
    ...publicKey
  }
}

export function getDid({ keyPair }: { keyPair: any }): IDID {
  return (
    keyPair.fingerprint
      ? `did:key:${keyPair.fingerprint()}`
      : `did:key:${keyPair.publicKeyMultibase}`
  ) as IDID
}

export function setKeyPairId({
  keyPair,
  did
}: {
  keyPair: any
  did: string
}): void {
  keyPair.id = keyPair.fingerprint
    ? `${did}#${keyPair.fingerprint()}`
    : `${did}#${keyPair.publicKeyMultibase}`
}

export async function getKeyAgreementKeyPair({
  contexts,
  verificationPublicKey
}: {
  contexts: string[]
  verificationPublicKey: IPublicKey
}): Promise<{ keyAgreementKeyPair?: any }> {
  // The KAK pair will use the source key's controller, but may generate
  // its own .id
  let keyAgreementKeyPair: any

  if (verificationPublicKey.type === ED25519_KEY_2020_TYPE) {
    contexts.push(X25519_2020_CONTEXT_URL)
  }

  switch (verificationPublicKey.type) {
    case ED25519_KEY_2020_TYPE: {
      keyAgreementKeyPair = X25519KeyAgreementKey2020.fromEd25519VerificationKey2020(
        { keyPair: verificationPublicKey }
      )
      break
    }
    case MULTIKEY_TYPE: {
      // FIXME: Add keyAgreementKeyPair interface for Multikey.
      break
    }
    default: {
      throw new Error(
        `Cannot derive key agreement key from verification key type
          "${verificationPublicKey.type}".`
      )
    }
  }

  return { keyAgreementKeyPair }
}

export function getMultibaseMultikeyHeader({
  value
}: {
  value: string
}): string {
  if (!value) {
    throw new TypeError('"publicKeyMultibase" must be a string.')
  }
  return value.slice(0, 4)
}

export function addKeyAgreementKeyContext({
  contexts,
  keyAgreementKeyPair
}: {
  contexts: string[]
  keyAgreementKeyPair: any
}): void {
  const { type } = keyAgreementKeyPair
  switch (type) {
    case X25519_2019_TYPE: {
      if (!contexts.includes(X25519_2019_CONTEXT_URL)) {
        contexts.push(X25519_2019_CONTEXT_URL)
      }
      break
    }
    case X25519_2020_TYPE: {
      if (!contexts.includes(X25519_2020_CONTEXT_URL)) {
        contexts.push(X25519_2020_CONTEXT_URL)
      }
      break
    }
    default: {
      throw new Error(`Unsupported key agreement key type, "${type}".`)
    }
  }
}

export async function getKeyPair({
  fromMultibase,
  publicKeyMultibase,
  publicKeyDescription
}: {
  fromMultibase?: FromMultibase
  publicKeyMultibase?: string
  publicKeyDescription?: KeyPair | IKeyPair
} = {}): Promise<{
  keyPair?: KeyPair | IKeyPair
  keyAgreementKeyPair: any
}> {
  let keyPair: KeyPair | IKeyPair | undefined
  if (fromMultibase && publicKeyMultibase) {
    keyPair = await fromMultibase({ publicKeyMultibase })
  } else {
    keyPair = publicKeyDescription
  }
  const type = keyPair?.type
  let keyAgreementKeyPair: any
  if (type === X25519_2020_TYPE || type === X25519_2019_TYPE) {
    keyAgreementKeyPair = keyPair
    keyPair = undefined
  }
  return { keyPair, keyAgreementKeyPair }
}
