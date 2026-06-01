/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import type { AbstractKeyPair } from '@interop/data-integrity-core'
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
  fromFingerprint: (options: {
    fingerprint: string
  }) => AbstractKeyPair | Promise<AbstractKeyPair>
}): FromMultibase {
  return async function fromMultibase({
    publicKeyMultibase
  }: {
    publicKeyMultibase: string
  }) {
    return fromFingerprint({ fingerprint: publicKeyMultibase })
  }
}
