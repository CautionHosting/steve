import { verify } from 'tee-attestation-js/nitro';
import rootCert from '../../../tests/e2e/fixtures/eval-root-cert.pem';

export function verifyAttestation(document, options) {
  return verify(document, { ...options, rootCert });
}
