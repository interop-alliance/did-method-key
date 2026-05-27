/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import { describe, it, expect } from 'vitest'
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey'
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { X25519KeyAgreementKey2019 } from '@digitalbazaar/x25519-key-agreement-key-2019'
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020'
import { driver } from '../../src/index.js'

const didKeyDriver = driver()
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey.from
})

describe('did:key method driver', () => {
  describe('get', () => {
    it('should get the DID Document for a did:key DID', async () => {
      const did = 'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      const keyId =
        'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T#' +
        'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      const didDocument: any = await didKeyDriver.get({ did })

      expect(didDocument.id).toBe(did)
      expect(didDocument['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1'
      ])
      expect(didDocument.authentication).toEqual([keyId])
      expect(didDocument.assertionMethod).toEqual([keyId])
      expect(didDocument.capabilityDelegation).toEqual([keyId])
      expect(didDocument.capabilityInvocation).toEqual([keyId])

      const [publicKey] = didDocument.verificationMethod
      expect(publicKey.id).toBe(keyId)
      expect(publicKey.type).toBe('Multikey')
      expect(publicKey.controller).toBe(did)
      expect(publicKey.publicKeyMultibase).toBe(
        'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      )

      // An ed25519 Multikey does not derive an X25519 key agreement key.
      expect(didDocument.keyAgreement).toBeUndefined()
    })

    it('should get the DID Document for an ecdsa multikey did', async () => {
      const did = 'did:key:zDnaeucDGfhXHoJVqot3p21RuupNJ2fZrs8Lb1GV83VnSo2jR'
      const keyId = `${did}#zDnaeucDGfhXHoJVqot3p21RuupNJ2fZrs8Lb1GV83VnSo2jR`
      const didKeyDriverMultikey = driver()

      didKeyDriverMultikey.use({
        multibaseMultikeyHeader: 'zDna',
        fromMultibase: EcdsaMultikey.from
      })

      const didDocument: any = await didKeyDriverMultikey.get({ did })

      expect(didDocument.id).toBe(did)
      expect(didDocument['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1'
      ])
      expect(didDocument.authentication).toEqual([keyId])
      expect(didDocument.assertionMethod).toEqual([keyId])
      expect(didDocument.capabilityDelegation).toEqual([keyId])
      expect(didDocument.capabilityInvocation).toEqual([keyId])

      const [publicKey] = didDocument.verificationMethod
      expect(publicKey.id).toBe(keyId)
      expect(publicKey.type).toBe('Multikey')
      expect(publicKey.controller).toBe(did)
      expect(publicKey.publicKeyMultibase).toBe(
        'zDnaeucDGfhXHoJVqot3p21RuupNJ2fZrs8Lb1GV83VnSo2jR'
      )
    })

    it('should get the DID Document for a X25519-based DID', async () => {
      const did = 'did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
      const keyId = `${did}#z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc`
      const didKeyDriverKak = driver()

      didKeyDriverKak.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2020.from
      })

      const didDocument: any = await didKeyDriverKak.get({ did })
      expect(didDocument.id).toBe(did)
      expect(didDocument['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/x25519-2020/v1'
      ])
      const [publicKey] = didDocument.keyAgreement
      expect(publicKey.id).toBe(keyId)
      expect(publicKey.type).toBe('X25519KeyAgreementKey2020')
      expect(publicKey.controller).toBe(did)
      expect(publicKey.publicKeyMultibase).toBe(
        'z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
      )
    })

    it('should resolve an individual key within the DID Doc', async () => {
      const did = 'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      const keyId = did + '#z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      const key = await didKeyDriver.get({ did: keyId })

      expect(key).toEqual({
        '@context': 'https://w3id.org/security/multikey/v1',
        id: keyId,
        type: 'Multikey',
        controller: did,
        publicKeyMultibase: 'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      })
    })

    it('should resolve an individual X25519-based DID', async () => {
      const did = 'did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
      const keyId = `${did}#z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc`
      const didKeyDriverKak = driver()

      didKeyDriverKak.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2020.from
      })
      const key = await didKeyDriverKak.get({ did: keyId })

      expect(key).toEqual({
        '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
        id: keyId,
        type: 'X25519KeyAgreementKey2020',
        controller: did,
        publicKeyMultibase: 'z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
      })
    })

    it('should resolve an individual ecdsa multikey did', async () => {
      const did = 'did:key:zDnaeucDGfhXHoJVqot3p21RuupNJ2fZrs8Lb1GV83VnSo2jR'
      const mutikeyDid = `${did}#zDnaeucDGfhXHoJVqot3p21RuupNJ2fZrs8Lb1GV83VnSo2jR`
      const didKeyDriverMultikey = driver()

      didKeyDriverMultikey.use({
        multibaseMultikeyHeader: 'zDna',
        fromMultibase: EcdsaMultikey.from
      })
      const key = await didKeyDriverMultikey.get({ did: mutikeyDid })

      expect(key).toEqual({
        '@context': 'https://w3id.org/security/multikey/v1',
        id: mutikeyDid,
        type: 'Multikey',
        controller: did,
        publicKeyMultibase: 'zDnaeucDGfhXHoJVqot3p21RuupNJ2fZrs8Lb1GV83VnSo2jR'
      })
    })
  })

  describe('fromKeyPair', () => {
    it('should generate DID document and get round trip', async () => {
      const publicKeyMultibase =
        'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      const keyPair = await Ed25519VerificationKey.from({ publicKeyMultibase })
      const { didDocument, keyPairs, methodFor }: any =
        await didKeyDriver.fromKeyPair({ verificationKeyPair: keyPair })

      const did = didDocument.id
      const keyId = didDocument.authentication[0]

      const verificationKeyPair = methodFor({ purpose: 'assertionMethod' })

      // An ed25519 Multikey does not derive an X25519 key agreement key.
      let err
      try {
        methodFor({ purpose: 'keyAgreement' })
      } catch (caughtError) {
        err = caughtError
      }
      expect(err).toBeDefined()

      expect(keyId).toBe(verificationKeyPair.id)
      expect(keyPairs.get(keyId).controller).toBe(did)
      expect(keyPairs.get(keyId).id).toBe(keyId)
      const fetchedDidDoc = await didKeyDriver.get({ did })
      expect(fetchedDidDoc).toEqual(didDocument)
    })

    it('should generate "EcdsaMultikey" DID document using keypair', async () => {
      const publicKeyMultibase =
        'zDnaeucDGfhXHoJVqot3p21RuupNJ2fZrs8Lb1GV83VnSo2jR'
      const keyPair = await EcdsaMultikey.from({ publicKeyMultibase })
      const didKeyDriverMultikey = driver()
      didKeyDriverMultikey.use({
        multibaseMultikeyHeader: 'zDna',
        fromMultibase: EcdsaMultikey.from
      })
      const { didDocument, keyPairs, methodFor }: any =
        await didKeyDriverMultikey.fromKeyPair({ verificationKeyPair: keyPair })
      const did = didDocument.id
      const keyId = didDocument.authentication[0]

      const verificationKeyPair = methodFor({ purpose: 'assertionMethod' })
      let err
      let keyAgreementKeyPair
      try {
        keyAgreementKeyPair = methodFor({ purpose: 'keyAgreement' })
      } catch (caughtError) {
        err = caughtError
      }
      expect(err).toBeDefined()
      expect(keyAgreementKeyPair).toBeUndefined()

      expect(keyId).toBe(verificationKeyPair.id)

      expect(keyPairs.get(keyId).controller).toBe(did)
      expect(keyPairs.get(keyId).id).toBe(keyId)
      const fetchedDidDoc = await didKeyDriverMultikey.get({ did })
      expect(fetchedDidDoc).toEqual(didDocument)
    })

    it('should generate DID document with verificationKeyPair and keyAgreementKeyPair', async () => {
      const publicKeyMultibaseForVerificationKeyPair =
        'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      const keyPairForVerification = await Ed25519VerificationKey.from({
        publicKeyMultibase: publicKeyMultibaseForVerificationKeyPair
      })
      const publicKeyMultibaseForKeyAgreementKeyPair =
        'z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
      const keyPairForKeyAgreement = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase: publicKeyMultibaseForKeyAgreementKeyPair
      })
      const localDriver = driver()
      localDriver.use({
        multibaseMultikeyHeader: 'z6Mk',
        fromMultibase: Ed25519VerificationKey.from
      })
      localDriver.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2020.from
      })
      const { didDocument, keyPairs, methodFor }: any =
        await localDriver.fromKeyPair({
          verificationKeyPair: keyPairForVerification,
          keyAgreementKeyPair: keyPairForKeyAgreement
        })
      const did = didDocument.id
      const keyId =
        `did:key:${publicKeyMultibaseForVerificationKeyPair}` +
        `#${publicKeyMultibaseForVerificationKeyPair}`
      const keyAgreementId =
        `did:key:${publicKeyMultibaseForKeyAgreementKeyPair}` +
        `#${publicKeyMultibaseForKeyAgreementKeyPair}`
      expect(didDocument['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1',
        'https://w3id.org/security/suites/x25519-2020/v1'
      ])
      expect(didDocument.authentication).toEqual([keyId])
      expect(didDocument.assertionMethod).toEqual([keyId])
      expect(didDocument.capabilityDelegation).toEqual([keyId])
      expect(didDocument.capabilityInvocation).toEqual([keyId])

      const [publicKey] = didDocument.verificationMethod
      expect(publicKey.id).toBe(keyId)
      expect(publicKey.type).toBe('Multikey')
      expect(publicKey.controller).toBe(did)
      expect(publicKey.publicKeyMultibase).toBe(
        publicKeyMultibaseForVerificationKeyPair
      )

      const [kak] = didDocument.keyAgreement
      const kakDid = `did:key:${publicKeyMultibaseForKeyAgreementKeyPair}`

      expect(kak.id).toBe(keyAgreementId)
      expect(kak.type).toBe('X25519KeyAgreementKey2020')
      expect(kak.controller).toBe(kakDid)
      expect(kak.publicKeyMultibase).toBe(
        publicKeyMultibaseForKeyAgreementKeyPair
      )

      const verificationKeyPair = methodFor({ purpose: 'assertionMethod' })
      const keyAgreementKeyPair = methodFor({ purpose: 'keyAgreement' })
      expect(keyAgreementKeyPair).toBeDefined()
      expect(verificationKeyPair).toBeDefined()
      expect(verificationKeyPair.id).toBe(keyId)
      expect(keyAgreementKeyPair.id).toBe(keyAgreementId)
      expect(keyPairs.get(keyId).controller).toBe(did)
      expect(keyPairs.get(keyAgreementId).controller).toBe(kakDid)
    })

    it('should generate DID document from X25519 key', async () => {
      const publicKeyMultibase =
        'z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
      const keyPair = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase
      })
      const didKeyDriverMultikey = driver()
      didKeyDriverMultikey.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2020.from
      })
      const { didDocument, keyPairs, methodFor }: any =
        await didKeyDriverMultikey.fromKeyPair({ keyAgreementKeyPair: keyPair })
      const did = didDocument.id
      const keyId = didDocument.keyAgreement[0].id
      const keyAgreementKeyPair = methodFor({ purpose: 'keyAgreement' })

      expect(keyId).toBe(keyAgreementKeyPair.id)

      expect(keyPairs.get(keyId).controller).toBe(did)
      expect(keyPairs.get(keyId).id).toBe(keyId)

      const fetchedDidDoc = await didKeyDriverMultikey.get({ did })
      expect(fetchedDidDoc).toEqual(didDocument)
    })
  })

  describe('use', () => {
    it('registers a key type from a keyPairClass', async () => {
      const localDriver = driver()
      localDriver.use({ keyPairClass: Ed25519VerificationKey })

      const did = 'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      const didDocument: any = await localDriver.get({ did })
      expect(didDocument.id).toBe(did)
      expect(didDocument.verificationMethod[0].type).toBe('Multikey')
    })

    it('throws if keyPairClass has no multibaseHeader', () => {
      const localDriver = driver()
      let error
      try {
        localDriver.use({
          keyPairClass: { from: Ed25519VerificationKey.from } as any
        })
      } catch (caughtError) {
        error = caughtError as Error
      }
      expect(error).toBeDefined()
      expect(error!.message).toContain('multibaseHeader')
    })
  })

  describe('generate', () => {
    it('generates a new DID document from the sole registered suite', async () => {
      const localDriver = driver()
      localDriver.use({ keyPairClass: Ed25519VerificationKey })

      const { didDocument, keyPairs, methodFor }: any =
        await localDriver.generate()

      const did = didDocument.id
      expect(did).toMatch(/^did:key:z6Mk/)
      expect(didDocument.verificationMethod[0].type).toBe('Multikey')

      const verificationKeyPair = methodFor({ purpose: 'assertionMethod' })
      expect(keyPairs.get(verificationKeyPair.id)).toBeDefined()

      // Generated doc round-trips through resolution.
      const fetchedDidDoc = await localDriver.get({ did })
      expect(fetchedDidDoc).toEqual(didDocument)
    })

    it('deterministically generates from a seed', async () => {
      const localDriver = driver()
      localDriver.use({ keyPairClass: Ed25519VerificationKey })

      const seed = new Uint8Array(32).fill(1)
      const first: any = await localDriver.generate({ seed })
      const second: any = await localDriver.generate({ seed })

      expect(first.didDocument.id).toMatch(/^did:key:z6Mk/)
      // Same seed yields the same DID Document.
      expect(first.didDocument).toEqual(second.didDocument)
      // A different seed yields a different DID.
      const other: any = await localDriver.generate({
        seed: new Uint8Array(32).fill(2)
      })
      expect(other.didDocument.id).not.toBe(first.didDocument.id)
    })

    it('selects a suite via keyType when several are registered', async () => {
      const localDriver = driver()
      localDriver.use({ keyPairClass: Ed25519VerificationKey })
      localDriver.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2020.from
      })

      const { didDocument }: any = await localDriver.generate({
        keyType: Ed25519VerificationKey
      })
      expect(didDocument.id).toMatch(/^did:key:z6Mk/)
    })

    it('throws when several suites are registered and no keyType is given', async () => {
      const localDriver = driver()
      localDriver.use({ keyPairClass: Ed25519VerificationKey })
      localDriver.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2020.from
      })

      let error
      try {
        await localDriver.generate()
      } catch (caughtError) {
        error = caughtError as Error
      }
      expect(error).toBeDefined()
      expect(error!.message).toContain('Multiple key suites registered')
    })

    it('throws when no suite is registered', async () => {
      const localDriver = driver()
      let error
      try {
        await localDriver.generate()
      } catch (caughtError) {
        error = caughtError as Error
      }
      expect(error).toBeDefined()
      expect(error!.message).toContain('No key suite registered')
    })

    it('throws when the registered suite cannot generate keys', async () => {
      const localDriver = driver()
      // Lower-level registration has no generator.
      localDriver.use({
        multibaseMultikeyHeader: 'z6Mk',
        fromMultibase: Ed25519VerificationKey.from
      })

      let error
      try {
        await localDriver.generate()
      } catch (caughtError) {
        error = caughtError as Error
      }
      expect(error).toBeDefined()
      expect(error!.message).toContain('cannot generate keys')
    })
  })

  describe('publicKeyToDidDoc', () => {
    it('should convert a key pair instance into a did doc', async () => {
      // Note that a freshly-generated key pair does not have a controller
      // or key id
      const keyPair = await Ed25519VerificationKey.generate()
      const { didDocument }: any = await didKeyDriver.publicKeyToDidDoc({
        publicKeyDescription: keyPair
      })

      expect(didDocument).toBeDefined()
      expect(didDocument).toHaveProperty('@context')
      expect(didDocument.id).toBe(`did:key:${keyPair.fingerprint()}`)
    })

    it('should convert a 2019 X25519-based key to a did doc', async () => {
      const localDriver = driver()
      localDriver.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2019.from
      })
      const keyPair = await X25519KeyAgreementKey2019.generate()
      const { didDocument }: any = await localDriver.publicKeyToDidDoc({
        publicKeyDescription: keyPair
      })
      expect(didDocument).toBeDefined()
      expect(didDocument).toHaveProperty('@context')
      expect(didDocument.id).toBe(`did:key:${keyPair.fingerprint()}`)
      expect(didDocument['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/x25519-2019/v1'
      ])
      const [publicKey] = didDocument.keyAgreement
      expect(publicKey.type).toBe('X25519KeyAgreementKey2019')
      expect(publicKey.controller).toBe(`did:key:${keyPair.fingerprint()}`)
    })

    it('should convert a 2020 X25519-based key to a did doc', async () => {
      const localDriver = driver()
      localDriver.use({
        multibaseMultikeyHeader: 'z6LS',
        fromMultibase: X25519KeyAgreementKey2020.from
      })
      const keyPair = await X25519KeyAgreementKey2020.generate()
      const { didDocument }: any = await localDriver.publicKeyToDidDoc({
        publicKeyDescription: keyPair
      })
      expect(didDocument).toBeDefined()
      expect(didDocument).toHaveProperty('@context')
      expect(didDocument.id).toBe(`did:key:${keyPair.fingerprint()}`)
      expect(didDocument['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/x25519-2020/v1'
      ])
      const [publicKey] = didDocument.keyAgreement
      expect(publicKey.type).toBe('X25519KeyAgreementKey2020')
      expect(publicKey.controller).toBe(`did:key:${keyPair.fingerprint()}`)
    })

    it('should convert a plain object to a did doc', async () => {
      const publicKeyDescription = {
        '@context': 'https://w3id.org/security/multikey/v1',
        id:
          'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T#' +
          'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T',
        type: 'Multikey',
        controller: 'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T',
        publicKeyMultibase: 'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      }
      const { didDocument }: any = await didKeyDriver.publicKeyToDidDoc({
        publicKeyDescription
      })

      expect(didDocument).toBeDefined()
      expect(didDocument).toHaveProperty('@context')
      expect(didDocument.id).toBe(
        'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      )
    })
  })

  describe('publicMethodFor', () => {
    it('should find a key for a did doc and purpose', async () => {
      const did = 'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      // First, get the did document
      const didDocument: any = await didKeyDriver.get({ did })

      const authKeyData = didKeyDriver.publicMethodFor({
        didDocument,
        purpose: 'authentication'
      })
      expect(authKeyData).toHaveProperty('type', 'Multikey')
      expect(authKeyData).toHaveProperty(
        'publicKeyMultibase',
        'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      )
    })

    it('should throw error if key is not found for purpose', async () => {
      const did = 'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
      // First, get the did document
      const didDocument: any = await didKeyDriver.get({ did })

      let error
      try {
        didKeyDriver.publicMethodFor({
          didDocument,
          purpose: 'invalidPurpose'
        })
      } catch (caughtError) {
        error = caughtError as Error
      }

      expect(error).toBeDefined()
      expect(error!.message).toContain('No verification method found for purpose')
    })
  })

  describe('interoperability', () => {
    it('resolves identically with @digitalbazaar/ed25519-multikey', async () => {
      const did = 'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'

      const interopDriver = driver()
      interopDriver.use({
        multibaseMultikeyHeader: 'z6Mk',
        fromMultibase: Ed25519VerificationKey.from
      })
      const digitalBazaarDriver = driver()
      digitalBazaarDriver.use({
        multibaseMultikeyHeader: 'z6Mk',
        fromMultibase: Ed25519Multikey.from
      })

      const interopDoc = await interopDriver.get({ did })
      const digitalBazaarDoc = await digitalBazaarDriver.get({ did })

      expect(interopDoc).toEqual(digitalBazaarDoc)
    })
  })

  describe('computeId', () => {
    const keyPair: any = { fingerprint: () => '12345' }

    it('should set the key id based on fingerprint', async () => {
      keyPair.id = await didKeyDriver.computeId({ keyPair })

      expect(keyPair.id).toBe('did:key:12345#12345')
    })
  })

  describe('method', () => {
    it('should return did method id', async () => {
      expect(didKeyDriver.method).toBe('key')
    })
  })
})
