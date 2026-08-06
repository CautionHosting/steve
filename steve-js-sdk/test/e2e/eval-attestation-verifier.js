import { verify } from 'tee-attestation-js/nitro';
import rootCert from '../../../tests/e2e/fixtures/eval-root-cert.pem';

export const ATTESTATION_PROFILE = Object.freeze({
  id: 'synthetic-eval',
  trustAnchor: 'STEVE Local Eval Root',
  synthetic: true
});

export function verifyAttestation(document, options) {
  return verify(document, { ...options, rootCert });
}
