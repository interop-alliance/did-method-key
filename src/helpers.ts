/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020'
import type {
  AbstractKeyPair,
  IDID,
  IDidDocument,
  IKeyPair,
  IPublicKey,
  IVerificationMethodEntry
} from '@interop/data-integrity-core'
import type { FromMultibase } from './types.js'

/**
 * Normalizes a DID Document verification-relationship value (which the data
 * model permits to be a single entry or an array) to an array.
 */
function toArray(
  value?: IVerificationMethodEntry | IVerificationMethodEntry[]
): IVerificationMethodEntry[] {
  if (value == null) {
    return []
  }
  return Array.isArray(value) ? value : [value]
}

const ED25519_KEY_2020_TYPE = 'Ed25519VerificationKey2020'
const ED25519_KEY_2020_CONTEXT_URL =
  'https://w3id.org/security/suites/ed25519-2020/v1'
// Multibase-multikey header (base58btc) for Ed25519 public keys.
const ED25519_MULTIKEY_HEADER = 'z6Mk'

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
  verificationPublicKey
}: {
  verificationPublicKey: IPublicKey
}): Promise<{ keyAgreementKeyPair?: any }> {
  // Detect Ed25519 by its multibase-multikey header (`z6Mk`) rather than the
  // suite `type`: Multikey-style suites export `type: 'Multikey'` for ed25519
  // keys, while the older 2020 suite reports `Ed25519VerificationKey2020`.
  // Both encode the public key as a base58btc `z6Mk...` multibase value, which
  // is all `fromEd25519VerificationKey2020()` needs to perform the conversion.
  const publicKeyMultibase = (
    verificationPublicKey as { publicKeyMultibase?: string }
  ).publicKeyMultibase
  const isEd25519 =
    verificationPublicKey.type === ED25519_KEY_2020_TYPE ||
    publicKeyMultibase?.startsWith(ED25519_MULTIKEY_HEADER)

  if (!isEd25519) {
    // Only Ed25519 verification keys can be converted into an X25519
    // keyAgreement key; nothing to derive for other key types.
    return { keyAgreementKeyPair: undefined }
  }

  // The KAK pair reuses the source key's controller, but generates its own .id
  const keyAgreementKeyPair =
    X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair: verificationPublicKey
    })

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
  contexts: Array<string | Record<string, unknown>>
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
  publicKeyDescription?: AbstractKeyPair | IKeyPair
} = {}): Promise<{
  keyPair?: AbstractKeyPair | IKeyPair
  keyAgreementKeyPair: any
}> {
  let keyPair: AbstractKeyPair | IKeyPair | undefined
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
