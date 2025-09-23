export {
  assertValidManifestSignature,
  computeManifestDigestHex,
  signManifestBundle,
  signManifestWithSecuritySigner,
  verifyManifestSignatureDetailed,
  verifyManifestSignatureWithSecuritySigner,
} from '../../../report/src/security/signer';

export type {
  ManifestDigest,
  ManifestSignatureBundle,
  SecuritySignerOptions,
  VerificationFailureReason,
  VerificationOptions,
  VerificationResult,
} from '../../../report/src/security/signer';
