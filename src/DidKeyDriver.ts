/*!
 * Copyright (c) 2021-2026 Digital Bazaar, Inc. All rights reserved.
 */
import { findVerificationMethod } from '@interop/did-io'
import {
  addKeyAgreementKeyContext,
  getDid,
  getKey,
  getKeyAgreementKeyPair,
  getKeyPair,
  getMultibaseMultikeyHeader,
  setKeyPairId
} from './helpers.js'
import type { DidGenerationResult, DidMethodDriver } from '@interop/did-io'
import type {
  AbstractKeyPair,
  IDID,
  IDidDocument,
  IKeyPair,
  IPublicKey,
  IVerificationMethod
} from '@interop/data-integrity-core'
import type { FromMultibase, KeyPairClass, RegisteredKeyType } from './types.js'

const DID_CONTEXT_URL = 'https://www.w3.org/ns/did/v1'

export class DidKeyDriver implements DidMethodDriver {
  method: string
  _allowedKeyTypes: Map<string, RegisteredKeyType>

  constructor() {
    // used by did-io to register drivers
    this.method = 'key'
    this._allowedKeyTypes = new Map()
  }

  /**
   * Registers a key type that this driver is allowed to handle, for both
   * resolution (`get()`) and generation (`generate()`).
   *
   * Preferred form: pass a `keyPairClass` (a KeyPair suite class). The driver
   * reads the multibase-multikey header, deserializer, and generator off the
   * class, so the caller never has to know the literal header.
   *
   * Lower-level form: pass a `multibaseMultikeyHeader` plus a `fromMultibase`
   * deserializer directly. Use this for suites that do not expose the
   * `keyPairClass` contract. Key types registered this way support resolution
   * but not `generate()`.
   *
   * @param options {object} - Options hashmap.
   * @param [options.keyPairClass] {KeyPairClass} - A KeyPair suite class
   *   exposing static `multibaseHeader`, `from`, and (optionally) `generate`.
   * @param [options.multibaseMultikeyHeader] {string} - The multibase-multikey
   *   header to register (lower-level form).
   * @param [options.fromMultibase] {Function} - A function that converts a
   *   `{publicKeyMultibase}` value into a key pair interface (lower-level form).
   * @param [options.enableEncryptionKeyDerivation] {boolean} - When `true`,
   *   resolving a `did:key` for this (Ed25519) key type also derives an X25519
   *   keyAgreement key from the verification key and adds it to the DID
   *   document, matching the did:key spec's Ed25519 expansion. Off by default,
   *   since reusing one key for both signing and key agreement is a weaker
   *   security posture; enable it only when you knowingly need to encrypt to
   *   plain Ed25519 `did:key` identities (e.g. JWE/DIDComm/EDV recipients).
   */
  use({
    keyPairClass,
    multibaseMultikeyHeader,
    fromMultibase,
    enableEncryptionKeyDerivation = false
  }: {
    keyPairClass?: KeyPairClass
    multibaseMultikeyHeader?: string
    fromMultibase?: FromMultibase
    enableEncryptionKeyDerivation?: boolean
  } = {}): void {
    if (keyPairClass) {
      const header = keyPairClass.multibaseHeader
      if (!(header && typeof header === 'string')) {
        throw new TypeError('"keyPairClass.multibaseHeader" must be a string.')
      }
      if (typeof keyPairClass.from !== 'function') {
        throw new TypeError('"keyPairClass.from" must be a function.')
      }
      this._allowedKeyTypes.set(header, {
        fromMultibase: keyPairClass.from,
        generate: keyPairClass.generate
          ? keyPairClass.generate.bind(keyPairClass)
          : undefined,
        enableEncryptionKeyDerivation
      })
      return
    }
    if (!(
      multibaseMultikeyHeader && typeof multibaseMultikeyHeader === 'string'
    )) {
      throw new TypeError('"multibaseMultikeyHeader" must be a string.')
    }
    if (typeof fromMultibase !== 'function') {
      throw new TypeError('"fromMultibase" must be a function.')
    }
    this._allowedKeyTypes.set(multibaseMultikeyHeader, {
      fromMultibase,
      enableEncryptionKeyDerivation
    })
  }

  /**
   * Generates a new key pair and returns its `did:key` method DID Document.
   * Requires a suite registered via `use({ keyPairClass })`, since the
   * lower-level `fromMultibase` registration has no key generator.
   *
   * @param options {object} - Options hashmap.
   * @param [options.keyType] {KeyPairClass | string} - Selects which registered
   *   suite to generate with, as either a KeyPair class or its
   *   multibase-multikey header. Optional when exactly one suite is registered;
   *   required (to disambiguate) when more than one is registered.
   * @param [options.seed] {Uint8Array} - An optional secret-key seed, passed
   *   through to the registered suite's `generate()` to deterministically
   *   derive the key pair. When omitted, the suite generates a random key pair.
   * @param [options.keyAgreementKeyPair] {object} - Optional keyAgreement key
   *   pair, passed through to `fromKeyPair()`.
   *
   * @returns {Promise<{didDocument: IDidDocument, keyPairs: Map<string, AbstractKeyPair>,
   *   methodFor: Function}>} Resolves with the generated DID Document and the
   *   corresponding key pairs (for storage in a KMS).
   */
  async generate({
    keyType,
    seed,
    keyAgreementKeyPair,
    ...generateOptions
  }: {
    keyType?: KeyPairClass | string
    seed?: Uint8Array
    keyAgreementKeyPair?: AbstractKeyPair | IKeyPair
    [key: string]: unknown
  } = {}): Promise<DidGenerationResult> {
    let multibaseMultikeyHeader: string | undefined
    if (keyType) {
      multibaseMultikeyHeader =
        typeof keyType === 'string' ? keyType : keyType.multibaseHeader
    } else if (this._allowedKeyTypes.size === 1) {
      ;[multibaseMultikeyHeader] = this._allowedKeyTypes.keys()
    } else if (this._allowedKeyTypes.size === 0) {
      throw new Error('No key suite registered; call "use({keyPairClass})".')
    } else {
      throw new Error(
        'Multiple key suites registered; specify which via "keyType".'
      )
    }

    const registered = this._allowedKeyTypes.get(multibaseMultikeyHeader!)
    if (!registered) {
      throw new Error(
        `Unsupported "multibaseMultikeyHeader", "${multibaseMultikeyHeader}".`
      )
    }
    if (!registered.generate) {
      throw new Error(
        `Registered suite "${multibaseMultikeyHeader}" cannot generate keys; ` +
          'register it via "use({keyPairClass})".'
      )
    }
    const verificationKeyPair = await registered.generate({
      seed,
      ...generateOptions
    })
    return this.fromKeyPair({ verificationKeyPair, keyAgreementKeyPair })
  }

  /**
   * Generates a DID `key` (`did:key`) method DID Document from a KeyPair.
   *
   * @param options {object} - Options hashmap.
   * @param [options.verificationKeyPair] {object} - A verification KeyPair.
   * @param [options.keyAgreementKeyPair] {object} - A keyAgreement KeyPair.
   *
   * @returns {Promise<{didDocument: IDidDocument, keyPairs: Map<string, AbstractKeyPair>,
   *   methodFor: Function}>} Resolves with the generated DID Document, along
   *   with the corresponding key pairs used to generate it (for storage in a
   *   KMS).
   */
  async fromKeyPair({
    verificationKeyPair,
    keyAgreementKeyPair
  }: {
    verificationKeyPair?: AbstractKeyPair | IKeyPair
    keyAgreementKeyPair?: AbstractKeyPair | IKeyPair
  } = {}): Promise<DidGenerationResult> {
    if (!(verificationKeyPair || keyAgreementKeyPair)) {
      throw new TypeError(
        '"verificationKeyPair" or "keyAgreementKeyPair" must be an object.'
      )
    }
    // keyPairs is a map of keyId to key pair instance, that includes the
    // verificationKeyPair above and the keyAgreementKey pair that is
    // optionally passed or derived from the passed verification key pair
    const { didDocument, keyPairs } = await this._keyPairToDidDocument({
      keyPair: verificationKeyPair,
      keyAgreementKeyPair
    })

    // convenience function that returns the public/private key pair instance
    // for a given purpose (authentication, assertionMethod, keyAgreement, etc).
    const methodFor = ({ purpose }: { purpose: string }): AbstractKeyPair => {
      const { id: methodId } = this.publicMethodFor({
        didDocument,
        purpose
      })
      return keyPairs.get(methodId!)!
    }
    return { didDocument, keyPairs, methodFor }
  }

  /**
   * Returns the public key (verification method) object for a given DID
   * Document and purpose. Useful in conjunction with a `.get()` call.
   *
   * @example
   * const didDocument = await didKeyDriver.get({did});
   * const authKeyData = didDriver.publicMethodFor({
   *   didDocument, purpose: 'authentication'
   * });
   * // You can then create a suite instance object to verify signatures etc.
   * const authPublicKey = await cryptoLd.from(authKeyData);
   * const {verify} = authPublicKey.verifier();
   *
   * @param options {object} - Options hashmap.
   * @param options.didDocument {IDidDocument} - DID Document (retrieved via a
   *   `.get()` or from some other source).
   * @param options.purpose {string} - Verification method purpose, such as
   *   'authentication', 'assertionMethod', 'keyAgreement' and so on.
   *
   * @returns {IPublicKey} Returns the public key object (obtained from
   *   the DID Document), without a `@context`.
   */
  publicMethodFor({
    didDocument,
    purpose
  }: {
    didDocument?: IDidDocument
    purpose?: string
  } = {}): IPublicKey {
    if (!didDocument) {
      throw new TypeError('The "didDocument" parameter is required.')
    }
    if (!purpose) {
      throw new TypeError('The "purpose" parameter is required.')
    }

    const method = findVerificationMethod({ doc: didDocument, purpose })
    if (!method) {
      throw new Error(`No verification method found for purpose "${purpose}"`)
    }
    return method as IPublicKey
  }

  /**
   * Returns a `did:key` method DID Document for a given DID, or a key document
   * for a given DID URL (key id).
   * Either a `did` or `url` param is required.
   *
   * @example
   * await resolver.get({did}); // -> did document
   * await resolver.get({url: keyId}); // -> public key node
   *
   * @param options {object} - Options hashmap.
   * @param [options.did] {string} - DID URL or a key id (either an ed25519 key
   *   or an x25519 key-agreement key id).
   * @param [options.url] {string} - Alias for the `did` url param, supported
   *   for better readability of invoking code.
   *
   * @returns {Promise<IDidDocument | IPublicKey>} Resolves to a DID
   *   Document or a public key node with context.
   */
  async get({
    did,
    url
  }: {
    did?: IDID | string
    url?: string
  } = {}): Promise<IDidDocument | IPublicKey> {
    did = did || url
    if (!did) {
      throw new TypeError('"did" must be a string.')
    }
    const [didAuthority, keyIdFragment] = did.split('#')
    const publicKeyMultibase = didAuthority!.substring('did:key:'.length)
    // get the multikey header from the public key value
    const multibaseMultikeyHeader = getMultibaseMultikeyHeader({
      value: publicKeyMultibase
    })

    const registered = this._allowedKeyTypes.get(multibaseMultikeyHeader)
    if (!registered) {
      throw new Error(
        `Unsupported "multibaseMultikeyHeader", "${multibaseMultikeyHeader}".`
      )
    }
    const { keyAgreementKeyPair, keyPair } = await getKeyPair({
      fromMultibase: registered.fromMultibase,
      publicKeyMultibase
    })
    const { didDocument } = await this._keyPairToDidDocument({
      keyPair,
      keyAgreementKeyPair
    })

    if (keyIdFragment) {
      // resolve an individual key
      return getKey({ didDocument, keyIdFragment })
    }
    // Resolve the full DID Document
    return didDocument
  }

  /**
   * Converts a public key object to a `did:key` method DID Document.
   * Note that unlike `generate()`, a `keyPairs` map is not returned. Use
   * `publicMethodFor()` to fetch keys for particular proof purposes.
   *
   * @param options {object} - Options hashmap.
   * @param options.publicKeyDescription {object} - Public key object
   *   used to generate the DID document (either an LDKeyPair instance
   *   containing public key material, or a "key description" plain object
   *   (such as that generated from a KMS)).
   *
   * @returns {Promise<{didDocument: IDidDocument}>} Resolves with the generated
   *   DID Document.
   */
  async publicKeyToDidDoc({
    publicKeyDescription
  }: {
    publicKeyDescription?: AbstractKeyPair | IKeyPair | IPublicKey
  } = {}): Promise<{ didDocument: IDidDocument }> {
    const { keyPair, keyAgreementKeyPair } = await getKeyPair({
      publicKeyDescription
    })
    const { didDocument } = await this._keyPairToDidDocument({
      keyPair,
      keyAgreementKeyPair
    })
    return { didDocument }
  }

  /**
   * Converts an Ed25519KeyPair object to a `did:key` method DID Document.
   *
   * @param options {object} - Options hashmap.
   * @param options.keyPair {object} - Key used to generate the DID
   *   document (either an LDKeyPair instance containing public key material,
   *   or a "key description" plain object (such as that generated from a KMS)).
   * @param [options.keyAgreementKeyPair] {object} - Optional
   *   keyAgreement key pair for generating did for keyAgreement.
   *
   * @returns {Promise<{didDocument: IDidDocument, keyPairs: Map<string, AbstractKeyPair>}>}
   *   Resolves with the generated DID Document, along with the corresponding
   *   key pairs used to generate it (for storage in a KMS).
   */
  async _keyPairToDidDocument({
    keyPair,
    keyAgreementKeyPair
  }: {
    keyPair?: AbstractKeyPair | IKeyPair
    keyAgreementKeyPair?: any
  } = {}): Promise<{
    didDocument: IDidDocument
    keyPairs: Map<string, AbstractKeyPair>
  }> {
    const keyPairs = new Map<string, AbstractKeyPair>()
    let didDocument: IDidDocument
    let publicDhKey
    // data-integrity-core v8's `ILDContext` allows inline context objects, so a
    // suite's exported `@context` entries may be strings or objects.
    const contexts: Array<string | Record<string, unknown>> = [DID_CONTEXT_URL]
    if (!keyPair && keyAgreementKeyPair) {
      addKeyAgreementKeyContext({ contexts, keyAgreementKeyPair })
      const did = getDid({ keyPair: keyAgreementKeyPair })
      keyAgreementKeyPair.controller = did
      setKeyPairId({ keyPair: keyAgreementKeyPair, did })
      publicDhKey = await keyAgreementKeyPair.export({ publicKey: true })
      keyPairs.set(keyAgreementKeyPair.id, keyAgreementKeyPair)
      didDocument = {
        '@context': [DID_CONTEXT_URL, ...contexts.slice(1)],
        id: did,
        keyAgreement: [publicDhKey]
      }
      return { didDocument, keyPairs }
    }
    const sourceKeyPair = keyPair!
    let verificationKeyPair: AbstractKeyPair
    if (
      'export' in sourceKeyPair &&
      typeof sourceKeyPair.export === 'function'
    ) {
      // A live key pair instance is self-describing, so use it directly. This
      // is why fromKeyPair()/generate() do not require a prior use() call.
      verificationKeyPair = sourceKeyPair
    } else {
      // A plain key description (e.g. from a KMS) must be rebuilt into a live
      // instance using the registered deserializer for its multibase header.
      const description = sourceKeyPair as {
        publicKeyMultibase?: string
        publicKeyBase58?: string
        fingerprint?: () => string | Promise<string>
      }
      let publicKeyMultibase = description.publicKeyMultibase
      if (!publicKeyMultibase && description.publicKeyBase58) {
        // handle backwards compatibility w/older key pair interfaces
        publicKeyMultibase = await description.fingerprint!()
      }
      const multibaseMultikeyHeader = getMultibaseMultikeyHeader({
        value: publicKeyMultibase!
      })
      const registered = this._allowedKeyTypes.get(multibaseMultikeyHeader)
      if (!registered) {
        throw new Error(
          `Unsupported "multibaseMultikeyHeader", "${multibaseMultikeyHeader}".`
        )
      }
      verificationKeyPair = await registered.fromMultibase({
        publicKeyMultibase: publicKeyMultibase!
      })
    }

    const did = getDid({ keyPair: verificationKeyPair })
    verificationKeyPair.controller = did
    // Now set the source key's id
    setKeyPairId({ keyPair: verificationKeyPair, did })
    // get the public components of verification keypair
    const verificationPublicKey = await verificationKeyPair.export({
      publicKey: true,
      includeContext: true
    })
    const verificationContext = verificationPublicKey['@context']
    if (verificationContext) {
      // the suite's exported `@context` may be a single URL or an array
      contexts.push(
        ...(Array.isArray(verificationContext)
          ? verificationContext
          : [verificationContext])
      )
    }
    // delete context from verificationPublicKey
    delete verificationPublicKey['@context']
    // derive the keyAgreement keypair from the verification key, but only when
    // the verification key's suite was registered with
    // `enableEncryptionKeyDerivation: true` (opt-in, off by default)
    const { enableEncryptionKeyDerivation } =
      this._allowedKeyTypes.get(
        getMultibaseMultikeyHeader({
          value: (verificationPublicKey as { publicKeyMultibase?: string })
            .publicKeyMultibase!
        })
      ) ?? {}
    if (!keyAgreementKeyPair && enableEncryptionKeyDerivation) {
      ;({ keyAgreementKeyPair } = await getKeyAgreementKeyPair({
        verificationPublicKey
      }))
    }

    // get the public components of keyAgreement keypair
    if (keyAgreementKeyPair) {
      addKeyAgreementKeyContext({ contexts, keyAgreementKeyPair })
      const did = getDid({ keyPair: keyAgreementKeyPair })
      if (!keyAgreementKeyPair.controller) {
        keyAgreementKeyPair.controller = did
      }
      if (!keyAgreementKeyPair.id) {
        setKeyPairId({ keyPair: keyAgreementKeyPair, did })
      }
      publicDhKey = await keyAgreementKeyPair.export({ publicKey: true })
    }

    // Compose the DID Document
    const verificationMethodId = verificationPublicKey.id!
    didDocument = {
      // Note that did:key does not have its own method-specific context,
      // and only uses the general DID Core context, and key-specific contexts.
      '@context': [DID_CONTEXT_URL, ...contexts.slice(1)],
      id: did,
      verificationMethod: [verificationPublicKey as IVerificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId],
      capabilityDelegation: [verificationMethodId],
      capabilityInvocation: [verificationMethodId]
    }
    if (publicDhKey) {
      didDocument.keyAgreement = [publicDhKey]
    }
    // create the key pairs map
    keyPairs.set(verificationKeyPair.id!, verificationKeyPair)
    if (keyAgreementKeyPair) {
      keyPairs.set(keyAgreementKeyPair.id, keyAgreementKeyPair)
    }

    return { didDocument, keyPairs }
  }

  /**
   * Computes and returns the id of a given key pair. Used by `did-io` drivers.
   *
   * @param options {object} - Options hashmap.
   * @param options.keyPair {object} - The key pair used when computing the
   *   identifier.
   *
   * @returns {Promise<string>} Returns the key's id.
   */
  async computeId({ keyPair }: { keyPair: AbstractKeyPair }): Promise<string> {
    return `did:key:${keyPair.fingerprint()}#${keyPair.fingerprint()}`
  }
}
