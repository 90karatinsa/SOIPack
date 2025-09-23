export {
  assertValidManifestSignature,
  computeManifestDigestHex,
  signManifestBundle,
  signManifestWithSecuritySigner,
  verifyManifestSignatureDetailed,
  verifyManifestSignatureWithSecuritySigner,
} from '@soipack/packager';

export type {
  ManifestDigest,
  ManifestSignatureBundle,
  SecuritySignerOptions,
  VerificationFailureReason,
  VerificationOptions,
  VerificationResult,
} from '@soipack/packager';
