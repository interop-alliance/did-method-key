/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import type { KeyPair } from '@digitalcredentials/keypair'
import type { FromMultibase } from './types.js'

/**
 * A utility function to create a multibase-multikey deserializer function.
 *
 * @param options {object} - Options hashmap.
 * @param options.fromFingerprint {Function} - A method that creates a KeyPair
 *   from a key fingerprint.
 *
 * @returns {FromMultibase} - Multibase-multikey deserializer.
 */
export function createFromMultibase({
  fromFingerprint
}: {
  fromFingerprint: (options: { fingerprint: string }) => KeyPair | Promise<KeyPair>
}): FromMultibase {
  return async function fromMultibase({
    publicKeyMultibase
  }: {
    publicKeyMultibase: string
  }) {
    return fromFingerprint({ fingerprint: publicKeyMultibase })
  }
}
