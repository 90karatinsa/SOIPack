# SOIPack Sunucusu Güvenlik Modeli

SOIPack REST API'si tenant bazlı yetkilendirme için iki katmanlı bir kimlik doğrulama modeli uygular:

1. **JWT Bearer belirteçleri** kiracı ve kullanıcı kimliğini taşır ve kapsam kontrolleri (`soipack.api`, `soipack.admin` gibi) mevcut davranışla aynı şekilde çalışır.
2. **API anahtarları** gelen isteğin kurumsal portala ait olduğunu kanıtlar ve kullanıcı rolü modelini devreye alır.

## API Anahtarı Yönetimi

API anahtarları `SOIPACK_API_KEYS` ortam değişkeni üzerinden yapılandırılır. Değer CSV formatındadır ve her giriş `anahtarEtiketi=anahtarDegeri:rol1|rol2` biçimini destekler. Etiket isteğe bağlıdır ve raporlama için kullanılır; roller belirtilmediğinde `reader` rolü atanır.

Örnek yapılandırma:

```
SOIPACK_API_KEYS="ci=ci-token-123:maintainer,ops=operations-secret:admin|maintainer,partner=partner-demo"
```

Bu tanımda:

- `ci-token-123` anahtarı CI boru hattına aittir ve `maintainer` haklarına sahiptir.
- `operations-secret` anahtarı operasyon ekibine aittir ve hem `admin` hem `maintainer` rolünde değerlendirilir.
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
