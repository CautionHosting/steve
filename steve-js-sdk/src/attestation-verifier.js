import { verify } from 'tee-attestation-js/nitro';

export const ATTESTATION_PROFILE = Object.freeze({
  id: 'aws-nitro',
  trustAnchor: 'AWS Nitro root CA',
  synthetic: false
});

// Production verification always uses the AWS Nitro root bundled by
// tee-attestation-js. The local E2E build replaces this module at bundle time.
export function verifyAttestation(document, options) {
  return verify(document, options);
}
