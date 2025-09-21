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

## REST API Sertleştirmeleri

- **HTTPS zorunluluğu**: @soipack/server yalnızca TLS sertifikası (`SOIPACK_TLS_CERT_PATH`) ve özel anahtarı (`SOIPACK_TLS_KEY_PATH`) sağlandığında başlatılır; düz HTTP dinleyicileri reddedilir. Yönetici uçları (`/v1/admin/cleanup` ve `/metrics`) için istemci sertifikası gereksinimi `SOIPACK_TLS_CLIENT_CA_PATH` ile etkinleştirilebilir ve yalnızca güvenilir istemci sertifikaları kabul edilir.
- **JWKS güvenliği**: JSON Web Key Set uç noktaları yalnızca HTTPS üzerinden çözümlenir; air-gap ortamlarında JWKS içeriği dosya sistemi üzerinden (`SOIPACK_AUTH_JWKS_PATH`) sağlanabilir. Uzak JWKS çağrıları zaman aşımı, tekrar deneme ve önbellekleme limitleriyle sarılarak yanıt vermeyen sağlayıcılar `503 JWKS_UNAVAILABLE` hatasıyla raporlanır.
- **İstek sınırlaması**: Uygulama katmanında kişi başı (`SOIPACK_RATE_LIMIT_IP_*`) ve kiracı başına (`SOIPACK_RATE_LIMIT_TENANT_*`) oran sınırlaması uygulanır. Limit aşılırsa `429` yanıtı döner ve `Retry-After` başlığı kullanılır.
- **Gövde boyutu**: JSON istekleri `SOIPACK_MAX_JSON_BODY_BYTES` sınırı ile korunur; sınır aşılırsa API `413 PAYLOAD_TOO_LARGE` hatası üretir ve büyük gövde analizleri başlamadan engellenir.
- **Lisans sınırları**: `X-SOIPACK-License` başlığından veya çok parçalı `license` alanından gelen veriler `SOIPACK_LICENSE_MAX_BYTES`/`SOIPACK_LICENSE_HEADER_MAX_BYTES` sınırlarıyla doğrulanır. Limitleri aşan içerik base64 çözülmeden reddedilir ve `413 LICENSE_TOO_LARGE` hatası döner; streaming uygulaması sayesinde bellek tüketimi kontrol altında tutulur.
- **Kalıcı dosya izinleri**: Sunucu `storage` dizinlerini `0750` ile oluşturur, içe aktarılan/paketlenen tüm dosyaları `0640` izinleriyle saklar ve mevcut POSIX sahipliklerini normalize eder. Böylece yalnızca uygulama kullanıcısı ve grup üyeleri artefaktlara erişebilir, dünya genelindeki okuyucu izinleri engellenir.
