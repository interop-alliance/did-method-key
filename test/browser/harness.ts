import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { driver } from '../../src/index.js'

/**
 * Resolves a did:key ed25519 DID using a driver registered with the
 * `@interop/ed25519-verification-key` suite. Exposed for the Playwright browser
 * test, which imports this module via its served path.
 *
 * @param did {string} - The did:key DID to resolve.
 *
 * @returns {Promise<any>} The resolved DID Document.
 */
export async function resolveEd25519(did: string): Promise<any> {
  const didKeyDriver = driver()
  didKeyDriver.use({
    multibaseMultikeyHeader: 'z6Mk',
    fromMultibase: Ed25519VerificationKey.from
  })
  return didKeyDriver.get({ did })
}
