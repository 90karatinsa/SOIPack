# SOIPack Sunucusu Güvenlik Modeli

SOIPack REST API'si tenant bazlı yetkilendirme için iki katmanlı bir kimlik doğrulama modeli uygular:

1. **JWT Bearer belirteçleri** kiracı ve kullanıcı kimliğini taşır ve kapsam kontrolleri (`soipack.api`, `soipack.admin` gibi) mevcut davranışla aynı şekilde çalışır.
2. **API anahtarları** gelen isteğin kurumsal portala ait olduğunu kanıtlar ve kullanıcı rolü modelini devreye alır.

## HTTP Güvenlik Başlıkları

Sunucu, Helmet yapılandırmasıyla gelen tüm yanıtlara aşağıdaki koruyucu başlıkları uygular:

- `Content-Security-Policy: default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; connect-src 'self'; font-src 'self'; img-src 'self' data:; manifest-src 'self'; media-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'; worker-src 'self'`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: accelerometer=(); autoplay=(); camera=(); display-capture=(); document-domain=(); encrypted-media=(); fullscreen=(); geolocation=(); gyroscope=(); magnetometer=(); microphone=(); midi=(); payment=(); picture-in-picture=(); publickey-credentials-get=(); sync-xhr=(); usb=(); xr-spatial-tracking=()`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Resource-Policy: same-origin`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-DNS-Prefetch-Control: off`
- `X-Permitted-Cross-Domain-Policies: none`

Ek olarak Express `X-Powered-By` üst bilgisi devre dışı bırakılır ve tüm isteklere benzersiz `X-Request-Id` değerleri atanır.

## SBOM Üretimi ve Dağıtımı

`@soipack/packager` her paket oluşturulduğunda SPDX 2.3 formatında bir Yazılım Malzeme Listesi (SBOM) üretir. SBOM dosyası `sbom.spdx.json` adıyla paket arşivinin köküne eklenir ve içerisindeki tüm rapor ve kanıt dosyalarını SHA-256 özetleriyle listeler. Paket manifesti, SBOM'un aynı algoritmayla hesaplanan karmasını `sbom` meta verisinde saklar; böylece SBOM bütünlüğü imza doğrulamasıyla birlikte denetlenebilir.

Operasyon ekipleri SBOM'u son kullanıcılara sunarken iki gereksinimi karşılamalıdır:

1. SBOM dosyası paket arşivinden çıkarılmadan doğrulanmalı, manifestteki `sbom.digest` alanı ile eşleştiği teyit edilmelidir.
2. Müşterilere sağlanan tüm kanıt paketleri SBOM dosyasını değişmeden içermeli ve SBOM'un bağımsız olarak indirildiği senaryolarda ilgili manifest imzası ile birlikte paylaşılmalıdır.

## API Anahtarı Yönetimi

API anahtarları `SOIPACK_API_KEYS` ortam değişkeni üzerinden yapılandırılır. Değer CSV formatındadır ve her giriş `anahtarEtiketi=anahtarDegeri:rol1|rol2` biçimini destekler. Etiket isteğe bağlıdır ve raporlama için kullanılır; roller belirtilmediğinde `reader` rolü atanır. Desteklenen roller `admin`, `operator`, `maintainer` ve `reader` değerleridir.

Örnek yapılandırma:

```
SOIPACK_API_KEYS="ci=ci-token-123:maintainer,ops=operations-secret:admin|operator,partner=partner-demo"
```

Bu tanımda:

- `ci-token-123` anahtarı CI boru hattına aittir ve `maintainer` haklarına sahiptir.
- `operations-secret` anahtarı operasyon ekibine aittir ve `admin` ile `operator` rollerini taşır; yönetim uç noktalarını görüntüleyebilir ancak yalnızca `admin` kullanıcılar kayıt oluşturup silebilir.
- `partner-demo` anahtarı herhangi bir rol belirtilmediği için varsayılan olarak `reader` olur.

## İstek Doğrulama Akışı

- Sağlık kontrolü (`/health`) dışında kalan tüm uç noktalar için bir API anahtarı zorunludur. İstekler `X-Api-Key` başlığında anahtarı taşımalıdır.
- Anahtar SHA-256 ile parmak izi alınarak güvenli biçimde eşleştirilir. Tanınmayan anahtarlar `401 UNAUTHORIZED` hatası döndürür.
- Anahtar doğrulandıktan sonra rol kontrolü uygulanır. Uygun rol sağlanmazsa `403 FORBIDDEN` hatası üretilir.
- JWT katmanı başarılı olmadan tenant bağlamı oluşturulmadığı için API anahtarı tek başına yeterli değildir.

## Roller

Aşağıdaki roller desteklenir:

| Rol | Açıklama |
| --- | --- |
| `admin` | Tüm yönetim uç noktalarına erişim sağlar; yönetici kapsamı ile birlikte kullanılır. |
| `operator` | Denetim ve operasyon görevlerini yürütür; RBAC kullanıcılarını ve rollerini görüntüleyebilir, paketleme ve iş kuyruğu operasyonlarını yönetir ancak yönetici onayı gerektiren değişiklikleri yapamaz. |
| `maintainer` | Paketleme ve kuyruğa iş gönderme gibi değiştirici operasyonlara erişir. |
| `reader` | Rapor ve kanıt kayıtlarını yalnızca görüntüleyebilir. |

API anahtarına tanımlanan roller JWT kapsamları ile birlikte değerlendirilir; her ikisinin de izin vermesi gerekir.

## İzleme ve Günlükleme

Başarılı doğrulamalarda anahtarın parmak izi (`tokenHash`) ve isteğe bağlı etiketi uygulama günlüklerine eklenir. Gerçek anahtar değerleri hiçbir zaman loglara yazılmaz.

## Kanıt Manifesti İmzalama

SOIPack CLI ve sunucusu, kanıt manifestlerini SHA-256 karması üzerinden JWS (JSON Web Signature) formatında imzalar:

1. Manifest dosyası kanonik biçime dönüştürülür; tüm dosya girdileri yol adına göre sıralanır.
2. Kanonik JSON içeriğinin SHA-256 karması hesaplanır ve `manifestDigest` olarak kaydedilir.
3. Varsayılan geliştirme sertifikası (`test/certs/dev.pem`) veya kullanıcı tarafından sağlanan X.509 sertifika demeti kullanılarak
   Ed25519 algoritmasıyla JWS oluşturulur. JWS başlığına (`x5c`) sertifikanın DER çıktısı eklenir.
4. İmza dosyası (`manifest.sig`) JWS dizgesi olarak yazılır ve manifest ile paketlenir.
5. Doğrulama aşamasında JWS imzası kontrol edilir, sertifika geçerlilik süresi (`validFrom`/`validTo`) kontrol edilir ve karmanın
   manifest içeriğiyle eşleştiği doğrulanır.

`soipack pack` ve sunucu paketleme kuyruğu imza üretiminden hemen sonra doğrulama yapar. Doğrulama başarısız olursa işlem
sonlandırılır ve zip arşivi oluşturulmaz. `soipack verify` komutu JWS içindeki sertifikayı veya komut satırından verilen sertifikayı
kullanarak imzayı doğrular; süre sonu veya imza uyuşmazlığı durumlarında `verificationFailed` koduyla sonlanır.

### PKCS#7 / CMS Eş-İmzaları

Uyumluluk ekipleri bazı senaryolarda JWS yanında PKCS#7 (CMS) yapılarının da sağlanmasını talep eder. `@soipack/packager`
kitaplığı Ed25519 imzasının yanına isteğe bağlı olarak bir CMS yükü ekleyebilir:

1. CMS için ayrı bir X.509 sertifika ve özel anahtar demeti (`cms.bundlePem`) belirtilir. Demet birden fazla sertifika içeriyorsa
   tamamı imza paketine gömülür.
2. Manifest kanonik JSON dizgesi CMS yapısının içeriği olarak imzalanır ve SHA-256 özet alanı doğrulama sırasında manifest özetiyle
   karşılaştırılır.
3. Ortaya çıkan CMS imzası `manifest.sig` çıktısına gömülü değildir; imza demetinde `cmsSignature` alanı altında hem PEM hem de DER
   (base64) olarak erişilebilir.
4. Doğrulama aşamasında `verifyManifestSignatureWithSecuritySigner` çağrısına CMS imzası verilirse CMS yükü okunur, imza ve digest
   tutarlılığı kontrol edilir ve beklenen sertifika belirtildiyse karşılaştırma yapılır. Eksik CMS imzası `CMS_SIGNATURE_MISSING`,
   yanlış sertifika `CMS_CERTIFICATE_MISMATCH` gibi deterministik hata kodları üretir.

CMS çıktısı, uyum paketi dizinine `manifest.cms` adıyla kopyalanarak harici araçların kullanımı için saklanmalıdır (bkz. CLI
rehberi).
