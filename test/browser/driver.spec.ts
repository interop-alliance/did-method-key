import { test, expect } from '@playwright/test'

test('resolves a did:key ed25519 DID in the browser', async ({ page }) => {
  await page.goto('/test/index.html')
  const didDocument = await page.evaluate(async () => {
    const { resolveEd25519 } = await import('/test/browser/harness.ts')
    return resolveEd25519(
      'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
    )
  })

  expect(didDocument.id).toBe(
    'did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
  )
  expect(didDocument['@context']).toEqual([
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/multikey/v1'
  ])
  expect(didDocument.verificationMethod[0].type).toBe('Multikey')
  expect(didDocument.verificationMethod[0].publicKeyMultibase).toBe(
    'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T'
  )
})
