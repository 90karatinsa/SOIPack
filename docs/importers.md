# Veri İçeri Aktarıcıları

SOIPack dış araçlardan gelen kalite verilerini `@soipack/adapters` paketindeki dönüştürücülerle işler. Bu belge, JUnit XML, LCOV ve ReqIF veri akışlarının yeni akış (streaming) temelli dönüştürücülerini özetler.

## Ortak yapı taşları

- **ParseResult**: Her dönüştürücü `{ data, warnings }` yapısını döndürür.
- **EvidenceIndex**: Dönüştürülen kayıtlar uyum matrisi ve raporlama katmanına kanıt olarak aktarılır.
- Yeni dönüştürücüler büyük dosyaları satır veya olay bazlı okuyarak bellek kullanımını sabit tutar.

## JUnit XML

Dosya: `packages/adapters/src/adapters/junit.ts`

- `parseJUnitStream(filePath)` fonksiyonu SAX tabanlı olarak `testcase` düğümlerini akış halinde işler.
- Hatalı XML belgesi tespit edildiğinde anlamlı mesajla hata fırlatılır.
- Başarılı çalışmalarda `TestResult` nesneleri üretilir ve gereksinim özellikleri (`<property name="requirements">`) otomatik ayrıştırılır.
- Üst düzey API `importJUnitXml` hataları yakalayıp uyarı listesine ekler.

## LCOV

Dosya: `packages/adapters/src/adapters/lcov.ts`

- LCOV raporları satır satır `readline` akışıyla işlenir; her `SF:` kaydı ayrı dosya özetine dönüştürülür.
- Bir dosyada hiç kayıt yoksa açıklayıcı hata mesajı iletildiğinden hatalı raporlar kolayca saptanır.
- Üretilen `CoverageReport` verileri test-harita eşleşmelerini (`TN:`) de içerir.
- Üst düzey API `importLcov` aynı işleyiciyi kullanarak uyarıları toplar.

## ReqIF

Dosya: `packages/adapters/src/adapters/reqif.ts`

- ReqIF belgeleri olay tabanlı olarak parse edilir ve her `SPEC-OBJECT` için ilk `THE-VALUE` değeri gereksinim metni olarak alınır.
- Eksik `THE-VALUE` alanları uyarı üretir; ciddi biçim bozuklukları hata fırlatır.
- Üst düzey API `importReqIF`, hataları yakalayarak kullanıcıya boş veri kümesi ve uyarı mesajı döndürür.

## Test ve doğrulama

- `npm run test:adapters` komutu yalnızca adapter birim testlerini çalıştırır.
- Büyük dosya senaryoları için testler geçici olarak >5 MB boyutunda örnek dosyalar üretir ve dönüştürücülerin bellek dostu davranışını doğrular.
- Yanlış biçimlendirilmiş dosyalar beklenen hata mesajlarıyla reddedilir ve testler bu durumları denetler.

Akış tabanlı yaklaşım, CI ortamında büyük verileri içe aktarırken bellek taşmalarını önler ve kullanıcıya daha güçlü geri bildirim sağlar.
