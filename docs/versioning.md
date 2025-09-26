# Snapshot sürümleme ve freeze akışı

SOIPack kanıt ve rapor üretim süreçlerinde her veri kümesi, Git benzeri bir snapshot kimliği ile versiyonlanır. Bu doküman, `SnapshotVersion` modelinin nasıl üretildiğini, kanıt yüklemelerinde hangi meta verilerin eklendiğini ve CLI ile sunucu tarafında freeze akışının nasıl çalıştığını açıklar.

## Snapshot kimliklerinin formatı

- Her kanıt kaydı için `timestamp` ve SHA-256 içerik karması birleştirilerek `YYYYMMDDTHHMMSSZ-deadbeef1234` formatında bir `snapshotId` oluşturulur.
- Aynı bilgiler kullanılarak `SnapshotVersion` nesnesi üretilir. Bu nesne:
  - `id`: yukarıdaki kısa kimlik,
  - `createdAt`: ISO8601 zaman damgası,
  - `fingerprint`: kanıt içeriğinin tam SHA-256 karması,
  - `isFrozen`: freeze işleminden sonra `true`,
  - `frozenAt`: dondurma zamanı (varsa)
  alanlarını içerir.
- Bir kiracıya ait tüm kanıtlar, SHA-256 karmaları sıralanıp `deriveFingerprint` fonksiyonu ile tekil bir fingerprint’e dönüştürülür. Bu fingerprint, analiz çıktılarındaki genel snapshot versiyonunu belirler.

## CLI tarafı

- `runImport` sırasında tüm kanıtlar için `snapshotId` hesaplanır ve çalışma alanı meta verisine `metadata.version` olarak kaydedilir.
- `runAnalyze`, `generateComplianceSnapshot` çıktısındaki `snapshot.version` bilgisini `snapshot.json` dosyasına yazar ve `analysis.json` içinde `metadata.version` olarak saklar.
- `runReport`, HTML/JSON raporlara `snapshot.version.id` değerini geçirerek rapor başlığında görüntülenmesini sağlar. Aynı kimlik `compliance.json` dosyasında `snapshotId` alanı olarak yer alır.
- Sunucu yapılandırmasını dondurmak için yeni `freeze` komutu eklenmiştir. Örnek kullanım:

  ```bash
  node packages/cli/dist/index.js freeze \
    --api https://soipack.example.com \
    --token $SOIPACK_TOKEN
  ```

  Komut, `/v1/config/freeze` uç noktasına POST isteği gönderir ve yanıt olarak aktif versiyonun `id`, `fingerprint` ve `frozenAt` alanlarını döndürür.
- `runPack` ve `package` komutları `--ledger`, `--ledger-key` ve `--ledger-key-id` bayraklarıyla paketleme ledger'ını yönetir. Komutlar `snapshot.json` dosyasını okuyup manifest karmasını hesaplar, `appendEntry` ile `ledger.json` dosyasına yeni bir kayıt ekler ve elde edilen ledger kökünü manifest imzasına dahil eder.

## Sunucu tarafı

- `/evidence/upload` uç noktası artık her yükleme için `snapshotId` üretiyor ve yanıt gövdesine `snapshotVersion` alanı ekliyor.
- Aynı içerik karmasıyla yapılan yinelenen yüklemeler 200 durum kodu ile mevcut kaydı döndürür; böylece süreç idempotent hale gelir.
- Freeze sonrası davranış:
  - `/v1/config/freeze` çağrısı mevcut fingerprint’i dondurur ve `isFrozen` bayrağını `true` yapar.
  - Freeze’den sonra yapılan tüm yeni kanıt yüklemeleri `409 CONFIG_FROZEN` hatası ile reddedilir.
- Sunucudaki snapshot versiyonları bellekte tutulur; yeniden başlatma sonrasında ilk istek fingerprint’i yeniden hesaplar ve versiyonu otomatik olarak oluşturur.
- Paketleme kuyruğu, her manifest üretiminde kiracıya özel `ledger.json` dosyasını günceller ve yeni `ledgerEntry` kayıtlarını SSE üzerinden yayınlar.

## Rapor çıktıları

- `compliance.html`, `trace.html` ve `gaps.html` başlıklarında `Snapshot: <ID>` satırı gösterilir; eğer versiyon dondurulduysa yanında “Donduruldu” etiketi yer alır.
- `compliance.json` içerisinde `snapshotId` ve `snapshotVersion` alanları bulunur, böylece dış sistemler raporu üreten verisetinin fingerprint’ini doğrulayabilir.

Freeze ve snapshot yönetimi hakkında daha fazla ayrıntı için CLI ve sunucu testlerine bakabilir, örnek kullanım senaryolarını `examples/minimal` dizinindeki pipeline akışında gözlemleyebilirsiniz.
