# @soipack/packager

SOIPack packager modülü, analiz ve rapor çıktılarınızı kanıt ekleriyle birlikte
kapsayan imzalı arşivler üretir. Paketleme işlemi sırasında oluşturulan
`manifest.json`, paket içeriğinin kriptografik özeti ve ledger zinciri hakkında
bilgi taşır. Manifest dosyası aynı zamanda `manifest.sig` tarafından imzalanır
ve `@soipack/packager` doğrulama yardımcıları ile denetlenebilir.

## Manifest yapısı

`buildManifest` fonksiyonu rapor klasörünü ve opsiyonel kanıt dizinlerini
okuyarak deterministik bir manifest döndürür. Manifest içerisinde her dosyanın
POSIX normalize edilmiş yolu ve SHA-256 özeti bulunur. Ek olarak manifest,
ledger zinciriyle ilişkili kök bilgilerini de içerir:

```json
{
  "createdAt": "2024-02-01T10:15:00.000Z",
  "toolVersion": "0.2.0",
  "files": [
    { "path": "reports/summary.txt", "sha256": "…" },
    { "path": "evidence/sample/log.csv", "sha256": "…" }
  ],
  "ledger": {
    "root": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "previousRoot": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
}
```

Ledger alanı yoksa `manifest.sig` imzası bir ledger kökü beklemez ve doğrulama
isteğe bağlıdır. Alan `null` ise manifest, zincire bağlı olmadığını açıkça ifade
eder.

## Paket oluşturma

`createSoiDataPack` fonksiyonu aşağıdaki adımları uygular:

1. Manifesti oluşturur ve opsiyonel ledger bilgilerini ekler.
2. Belirtilen kimlik bilgileriyle manifesti imzalar.
3. İmzanın dosya listesi ve ledger kökleriyle tutarlı olduğunu doğrular.
4. `manifest.json`, `manifest.sig` ve CMS imzası etkinse `manifest.cms`
   dosyalarıyla birlikte rapor ve kanıt içeriklerini ZIP arşivine yazar.

İşlev başarıyla tamamlandığında çıktıda hem manifest hem de imza değeri
bulunur. `manifest.ledger` ile `verifyManifestSignatureDetailed` sonuçlarındaki
`ledgerRoot`/`previousLedgerRoot` alanlarının eşleşmesi garanti altındadır.

## SPHINCS+ worker temizliği

Paketleyici, yerel ortamda yerleşik SPHINCS+ uygulaması bulunmadığında
operasyonları bir worker betiği üzerinden yürütür. Betik, çalışma zamanında
`/tmp/sphincs-worker-*` altında oluşturulan geçici bir dizinde tutulur.
Süreç sonlandığında bu geçici dizin otomatik olarak silinir. Uzun süreli
betikler için gerektiğinde `cleanupSphincsWorker()` fonksiyonunu çağırarak
temizlik işlemi manuel olarak da tetiklenebilir.

```ts
import { createSoiDataPack } from '@soipack/packager';

const { manifest, signature, outputPath } = await createSoiDataPack({
  reportDir: './out/report',
  evidenceDirs: ['./out/evidence'],
  toolVersion: '0.2.0',
  credentialsPath: './keys/dev.pem',
  cms: { bundlePath: './keys/cms.pem' },
  ledger: {
    root: 'aaaaaaaa…',
    previousRoot: 'bbbbbbbb…',
  },
});
```

Oluşturulan paket, zincirin beklenen köküyle eşleşmediğinde hata verir ve
imzalar yüklenirken ledger sürekliliğinin otomatik olarak doğrulanmasını sağlar.
CMS imzası sağlandığında arşivde `manifest.cms` dosyası üretilir ve dönen sonuç
nesnesindeki `cmsSignature` alanı SHA-256 özeti ile DER çıktı doğrulamasını
kolaylaştırır.
