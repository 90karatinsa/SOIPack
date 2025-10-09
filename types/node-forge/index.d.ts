declare module 'node-forge' {
  namespace forge {
    namespace pkcs7 {
      type PkcsSignedData = any;
    }
    namespace asn1 {
      type Asn1 = any;
    }
    namespace util {
      type ByteBuffer = { bytes(): string; getBytes(): string };
    }
    namespace pki {
      type Certificate = any;
      const oids: Record<string, string>;
    }
    namespace md {
      type MessageDigest = { update(data: string, encoding?: string): void; digest(): util.ByteBuffer };
    }
    namespace random {
      function getBytesSync(count: number): string;
    }
  }

  type ForgeModule = {
    pkcs7: {
      createSignedData(): forge.pkcs7.PkcsSignedData;
      messageFromPem(pem: string): forge.pkcs7.PkcsSignedData;
      messageFromAsn1(obj: any): forge.pkcs7.PkcsSignedData;
      messageToPem(message: any): string;
    };
    asn1: {
      Class: any;
      Type: any;
      fromDer(input: string | forge.util.ByteBuffer): forge.asn1.Asn1;
      toDer(obj: forge.asn1.Asn1): { getBytes(): string };
      derToOid(der: any): string;
      create(tagClass: number, type: number, constructed: boolean, value: any): forge.asn1.Asn1;
    };
    util: {
      createBuffer(input?: string, encoding?: string): forge.util.ByteBuffer;
    };
    pki: {
      oids: typeof forge.pki.oids;
      certificateFromPem(pem: string): forge.pki.Certificate;
      certificateToPem(cert: forge.pki.Certificate): string;
      createCaStore(certs?: string | string[]): any;
      verifyCertificateChain(store: any, chain: forge.pki.Certificate[], options?: any): boolean;
      publicKeyFromPem(pem: string): any;
      privateKeyFromPem(pem: string): any;
    };
    md: {
      sha256(): forge.md.MessageDigest;
    };
    random: {
      getBytesSync(count: number): string;
    };
  };

  const forge: ForgeModule;
  export = forge;
}
