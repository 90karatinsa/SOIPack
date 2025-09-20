# SOIPack Güvenlik ve Bütünlük Notları

SOIPack, gereksinim izlenebilirliği sonuçlarını paketlerken manifest imzası ve kontrollü anahtar yönetimiyle bütünlüğü korumayı hedefler. Bu doküman, demo ortamındaki güvenlik varsayımlarını üretim senaryolarına taşımak için izlenmesi gereken yöntemleri özetler.

## Anahtar Yönetimi

- **Ed25519 anahtar çifti**: Paket imzaları Ed25519 algoritmasıyla üretilir. Demo kurulumu OpenSSL ile aşağıdaki komutla uyumlu anahtar üretimini örnekler; aynı akış üretim anahtarının hazırlanması için de geçerlidir.【F:README.md†L75-L88】
- **Anahtar depolama**: Özel anahtarlar (örn. `ed25519_private.pem`) hava boşluklu (air-gap) bir anahtar kasasında veya donanımsal güvenlik modülünde saklanmalıdır. SOIPack pipeline'ı anahtarı diskten okur, bu nedenle çalışma zamanında sadece imzalama adımının gerçekleştiği izole ortamlarda kullanılmalıdır.
- **Anahtar rotasyonu**: `manifest.json` içindeki `signer` alanı (üretim senaryosunda özelleştirilmelidir) yeni anahtara geçişleri kayıt altına almak için kullanılabilir. Yeni anahtara geçildiğinde önceki manifestlerin doğrulanabilirliği sağlanmalı ve kamu anahtarları tüketicilerle güvenli kanallardan paylaşılmalıdır.

## İmza Akışı

1. **Rapor üretimi**: `node packages/cli/dist/index.js report` komutu `dist/reports/` altında HTML ve PDF raporları oluşturur; bunlar `compliance_matrix.html`, `trace_matrix.html` ve `compliance_matrix.pdf` dosyalarını içerir.【F:docs/demo_script.md†L18-L25】
2. **Manifest oluşturma**: `pack` komutu `dist/` dizinini tarar, içerik karmalarını çıkarır ve sonuçları `release/manifest.json` dosyasında toplar.【F:packages/cli/src/index.ts†L556-L654】
3. **İmza üretimi**: Aynı adımda manifestin SHA-256 özeti `release/manifest.sig` dosyasına yazılır; üretim ortamında bu değer Ed25519 özel anahtarıyla imzalanmış base64 çıktıyla değiştirilmelidir.【F:packages/cli/src/index.ts†L612-L654】
4. **Arşivleme**: Manifest ve imza `release/soi-pack-*.zip` paketine dahil edilir. Demo senaryosunda `scripts/make-demo.sh` bu arşivi uçtan uca üretir ve terminalde yolları raporlar.【F:docs/demo_script.md†L26-L31】
5. **Doğrulama**: Paket tüketicileri manifestin karmasını yeniden hesaplayıp `manifest.sig` ile karşılaştırmalı; hava boşluklu ortamlarda doğrulama ofline yapılır.

## Air-Gap ve İzolasyon

- **Hazırlık aşaması**: Veri içe aktarma (`import`) ve analiz (`analyze`) adımları çevrimdışı çalışabilir. Air-gap senaryosunda örnek veriler USB/taşınabilir disk üzerinden izole ortama getirilmeli ve `scripts/make-demo.sh` veya YAML pipeline konfigürasyonu air-gap içinde çalıştırılmalıdır.【F:docs/demo_script.md†L10-L31】【F:README.md†L36-L73】
- **Lisans doğrulaması**: `verifyLicenseFile` adımı lisans dosyasını okumak için yerel dosya erişimi kullanır; dış ağ çağrısı yapılmaz, bu da air-gap uyumluluğunu destekler.【F:packages/cli/src/index.ts†L40-L115】
- **Çıkış materyalleri**: Üretilen `release/soi-pack-*.zip` paketi hava boşluklu ağdan ayrılmadan önce bir offline virüs taramasından geçirilmeli, ardından fiziksel medyayla müşteri ağına taşınmalıdır.
- **İz kayıtları**: `manifest.json` içindeki tarih damgası (`generatedAt`) sabitlenmiş demo zaman damgasıyla (`SOIPACK_DEMO_TIMESTAMP`) veya gerçek zamanlı saatle üretilir. Air-gap ortamında saat senkronizasyonu güvenilir NTP yerine kontrollü manuel prosedürlerle yapılmalıdır.【F:packages/cli/src/index.ts†L48-L115】

Bu prosedürler, demo çıktılarındaki raporların ve manifestlerin denetlenebilirliğini korurken, üretim süreçlerinde uyarlanabilir güvenlik kontrolleri sağlar.
