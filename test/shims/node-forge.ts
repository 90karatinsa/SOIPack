import { createHash, createPrivateKey, createPublicKey, createSign, randomBytes, X509Certificate } from 'crypto';

type ByteBufferLike = {
  bytes: () => string;
  getBytes: () => string;
  length: () => number;
};

class ForgeByteBuffer implements ByteBufferLike {
  private readonly buffer: Buffer;

  constructor(buffer: Buffer) {
    this.buffer = buffer;
  }

  bytes(): string {
    return this.buffer.toString('binary');
  }

  getBytes(): string {
    return this.bytes();
  }

  length(): number {
    return this.buffer.length;
  }

  toBuffer(): Buffer {
    return Buffer.from(this.buffer);
  }
}

type CmsPayload = {
  content: string;
  signature: string;
  digestAlgorithmOid: string;
  certificatePem: string;
  signatureAlgorithmOid: string;
  serialNumber?: string;
  issuer?: string;
  subject?: string;
};

const normalizePem = (pem: string): string => {
  const trimmed = pem.trim();
  return trimmed.endsWith('\n') ? trimmed : `${trimmed}\n`;
};

const OIDS = {
  sha256: '1.2.840.113549.2.9',
  sha256WithRSAEncryption: '1.2.840.113549.1.1.11',
  contentType: '1.2.840.113549.1.9.3',
  data: '1.2.840.113549.1.7.1',
  messageDigest: '1.2.840.113549.1.9.4',
  signedData: '1.2.840.113549.1.7.2',
  certificateList: '1.2.840.113549.1.9.23',
};

class ForgeCertificate {
  public readonly pem: string;
  public readonly signatureOid: string;
  public readonly siginfo: { algorithmOid: string };
  public readonly publicKey: ReturnType<typeof createPublicKey>;
  public readonly serialNumber: string;
  public readonly issuer: string;
  public readonly subject: string;

  constructor(pem: string) {
    this.pem = normalizePem(pem);
    const x509 = new X509Certificate(this.pem);
    this.publicKey = createPublicKey(this.pem);
    this.serialNumber = x509.serialNumber;
    this.issuer = x509.issuer;
    this.subject = x509.subject;
    this.signatureOid = OIDS.sha256WithRSAEncryption;
    this.siginfo = { algorithmOid: this.signatureOid };
  }
}

class SignedData {
  private certificates: ForgeCertificate[] = [];
  private signer?: {
    key: ReturnType<typeof createPrivateKey>;
    certificate: ForgeCertificate;
    digestAlgorithm?: string;
  };
  private contentBuffer: Buffer = Buffer.alloc(0);
  private contentByteBuffer: ForgeByteBuffer = new ForgeByteBuffer(Buffer.alloc(0));
  private payloadBuffer: Buffer = Buffer.alloc(0);
  private payload?: CmsPayload;

  set content(buffer: ForgeByteBuffer | string) {
    if (buffer instanceof ForgeByteBuffer) {
      this.contentByteBuffer = buffer;
      this.contentBuffer = buffer.toBuffer();
    } else if (typeof buffer === 'string') {
      const resolved = Buffer.from(buffer, 'binary');
      this.contentByteBuffer = new ForgeByteBuffer(resolved);
      this.contentBuffer = resolved;
    }
  }

  get content(): ForgeByteBuffer {
    return this.contentByteBuffer;
  }

  addCertificate(certificate: ForgeCertificate): void {
    this.certificates.push(certificate);
  }

  addSigner(options: {
    key: string | ReturnType<typeof createPrivateKey>;
    certificate: ForgeCertificate;
    digestAlgorithm: string;
  }): void {
    const key =
      typeof options.key === 'string' ? createPrivateKey(normalizePem(options.key)) : options.key;
    this.signer = {
      key,
      certificate: options.certificate,
      digestAlgorithm: options.digestAlgorithm,
    };
  }

  sign(): void {
    if (!this.signer) {
      throw new Error('No signer configured.');
    }
    const signer = createSign('RSA-SHA256');
    signer.update(this.contentBuffer);
    signer.end();
    const signature = signer.sign(this.signer.key);
    const certificate = this.signer.certificate;

    const payload: CmsPayload = {
      content: this.contentBuffer.toString('utf8'),
      signature: signature.toString('base64'),
      digestAlgorithmOid: this.signer.digestAlgorithm ?? OIDS.sha256,
      certificatePem: forge.pki.certificateToPem(
        this.certificates[0] ?? this.signer.certificate,
      ),
      signatureAlgorithmOid: OIDS.sha256WithRSAEncryption,
      serialNumber: certificate.serialNumber,
      issuer: certificate.issuer,
      subject: certificate.subject,
    };

    this.payload = payload;
    this.payloadBuffer = Buffer.from(JSON.stringify(payload), 'utf8');
  }

  toAsn1(): { __payload: Buffer } {
    return { __payload: this.payloadBuffer };
  }

  getPayload(): Buffer {
    return this.payloadBuffer;
  }
}

const formatPemBody = (body: string): string => {
  return body.match(/.{1,64}/g)?.join('\n') ?? body;
};

const decodePemPayload = (pem: string): Buffer => {
  const body = pem
    .replace('-----BEGIN PKCS7-----', '')
    .replace('-----END PKCS7-----', '')
    .replace(/\s+/g, '');
  return Buffer.from(body, 'base64');
};

const buildSignedMessage = (payloadBuffer: Buffer) => {
  if (payloadBuffer.length === 0) {
    throw new Error('Empty CMS payload.');
  }
  const payload = JSON.parse(payloadBuffer.toString('utf8')) as CmsPayload;
  const contentBuffer = Buffer.from(payload.content, 'utf8');
  const byteBuffer = new ForgeByteBuffer(contentBuffer);
  const certificate = forge.pki.certificateFromPem(payload.certificatePem);
  const signatureBinary = Buffer.from(payload.signature, 'base64').toString('binary');

  return {
    content: byteBuffer,
    certificates: [certificate],
    rawCapture: {
      digestAlgorithm: payload.digestAlgorithmOid,
      signature: signatureBinary,
      certificatePem: payload.certificatePem,
      signerSerialNumber: payload.serialNumber,
      signerIssuer: payload.issuer,
      signerSubject: payload.subject,
    },
  };
};

const forge = {
  pkcs7: {
    createSignedData: () => new SignedData(),
    messageFromPem: (pem: string) => buildSignedMessage(decodePemPayload(pem)),
    messageFromAsn1: (asn1: { __payload?: Buffer }) => {
      if (!asn1 || !asn1.__payload) {
        throw new Error('ASN.1 payload missing.');
      }
      return buildSignedMessage(asn1.__payload);
    },
    messageToPem: (signedData: SignedData) => {
      const payload = signedData.getPayload();
      const body = payload.toString('base64');
      return `-----BEGIN PKCS7-----\n${formatPemBody(body)}\n-----END PKCS7-----\n`;
    },
  },
  asn1: {
    fromDer: (binary: string) => ({ __payload: Buffer.from(binary, 'binary') }),
    toDer: (asn1: { __payload?: Buffer }) => ({
      getBytes: () => (asn1.__payload ?? Buffer.alloc(0)).toString('binary'),
    }),
    derToOid: (value: string) => {
      switch (value) {
        case 'sha256':
          return OIDS.sha256;
        case 'sha256WithRSAEncryption':
          return OIDS.sha256WithRSAEncryption;
        default:
          return value;
      }
    },
    create: (tagClass: number, type: number, _constructed: boolean, value: unknown) => ({
      tagClass,
      type,
      value,
    }),
    Class: { UNIVERSAL: 0, CONTEXT_SPECIFIC: 1 } as const,
    Type: { SET: 0x11, OCTETSTRING: 0x04 } as const,
  },
  util: {
    createBuffer: (value: string | Buffer, encoding: BufferEncoding = 'binary') => {
      const buffer = typeof value === 'string' ? Buffer.from(value, encoding) : Buffer.from(value);
      return new ForgeByteBuffer(buffer);
    },
  },
  pki: {
    oids: OIDS,
    certificateFromPem: (pem: string) => new ForgeCertificate(pem),
    certificateToPem: (certificate: ForgeCertificate) => certificate.pem,
    createCaStore: () => ({}),
    verifyCertificateChain: () => true,
    publicKeyFromPem: (pem: string) => createPublicKey(normalizePem(pem)),
    privateKeyFromPem: (pem: string) => createPrivateKey(normalizePem(pem)),
  },
  md: {
    sha256: () => {
      const hash = createHash('sha256');
      return {
        update: (data: string | ByteBufferLike) => {
          if (typeof data === 'string') {
            hash.update(Buffer.from(data, 'binary'));
          } else if (data && typeof data.bytes === 'function') {
            hash.update(Buffer.from(data.bytes(), 'binary'));
          }
        },
        digest: () => ({ getBytes: () => hash.digest().toString('binary') }),
      };
    },
  },
  random: {
    getBytesSync: (count: number) => randomBytes(count).toString('binary'),
  },
};

module.exports = forge;
