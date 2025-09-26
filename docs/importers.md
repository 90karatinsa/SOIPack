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

## Manuel DO-178C artefakt eşlemeleri

- `--import artefakt=dosya` sözdizimi tüm DO-178C artefakt türleri için geçerlidir (ör. `plan`, `standard`, `qa_record`, `conformity`).
- CLI her eşlemeyi kanıt indeksine `source=other` olarak kaydeder ve SHA-256 karmasını hesaplar.
- Birden fazla dosya aynı artefakt türüne eşlenebilir; her dosya ayrı kanıt kaydı üretir.

## Jira gereksinimleri ve problem raporları

- `importJiraCsv(path)` gereksinim CSV dışa aktarımındaki temel sütunları (`Issue key`, `Summary`, `Status`) okuyarak `JiraRequirement` listesi üretir.
- `Issue Type` sütunu opsiyoneldir ancak `Bug`, `Defect`, `Problem Report` gibi türleri tespit ettiğinde kayıt `issueType` alanına yazılır.
- CLI `--jira` bayrağıyla verilen dosyaları `trace` kanıtı olarak kaydeder ve gereksinimleri çalışma alanına ekler.
- `--jira-defects` bayrağı aynı dönüştürücüyü kullanarak `Issue Type` değeri `Bug`/`Defect` olan satırları `problem_report` kanıtı olarak ekler, açık (`Status` ≠ `Done/Closed/Resolved`) ve toplam kayıt sayılarını çalışma alanı metaverisine işler.
- Eksik `Issue Type` sütunları veya eşleşmeyen satırlar kullanıcıya uyarı olarak iletilir; yine de CSV dosyasının tamamı kanıt olarak saklanır.

## Jama REST API entegrasyonu

- `fetchJamaArtifacts(options)` Jama Cloud ya da şirket içi dağıtımların REST API uç noktalarından gereksinim, test ve ilişki kayıtlarını okuyup tek bir `ImportBundle` yapısına dönüştürür.
- Zorunlu parametreler `baseUrl`, `projectId` ve `token` (REST API erişim jetonu) değerleridir; `pageSize`, `maxPages`, `timeoutMs` ve özel uç nokta şablonları gerektiğinde özelleştirilebilir.
- Dönüştürücü, Jama sayfa yapısını `pageInfo.next` veya `links.next` alanlarından takip eder; `Retry-After` üstbilgisine göre bekleyerek oran sınırı (rate limit) hatalarını otomatik olarak yeniden dener.
- Jama öğelerindeki HTML açıklamalar temizlenir, eksik başlıklar için uyarılar üretilir ve test-gereksinim ilişkileri `trace` kanıtları olarak `traceLinks` listesine eklenir. Her test kaydı, bağlı gereksinim kimliklerini `requirementsRefs` alanında taşır.
- REST API kullanımının mümkün olmadığı ortamlarda Jama raporlarını CSV/Excel olarak dışa aktarabilir, ardından CSV dosyalarını `importJiraCsv` veya özel dönüştürücülerle SOIPack’e alarak kanıt indeksine ekleyebilirsiniz.

## QA denetim kayıtları

Dosya: `packages/adapters/src/qaLogs.ts`

- `importQaLogs(path)` fonksiyonu QA denetim imza CSV'lerini satır bazlı olarak işler.
- Gerekli sütunlar: `Objective` (veya `Objective ID`) ve `Status`. Opsiyonel sütunlar `Artifact`, `Reviewer`, `Completed At`, `Notes` olarak eşleştirilir.
- Her satır `qa_record` kanıt özeti üretir; boş satırlar atlanır, eksik sütunlar uyarı olarak döndürülür.
- CLI `--qa` bayrağıyla verilen dosyaları okuyup QA kayıtlarını A-7 hedeflerine otomatik olarak bağlar.

## Statik analiz bulguları

- `fromPolyspace(path)` JSON raporlarındaki hata/uyarı kayıtlarını okuyarak `analysis` kategorisinde bulgular üretir, aynı dosyayı `review` ve `problem_report` kanıtı olarak işaretler.
- `fromLDRA(path)` kapsam metrikleriyle birlikte kural ihlallerini döndürür; CLI bu çıktıları `coverage_stmt` ve `problem_report` artefaktlarına dağıtır.
- `fromVectorCAST(path)` kapsam özetlerini ve test bazlı bulguları ayrıştırır; MC/DC gibi metrikler tespit edilirse ilgili DO-178C artefaktlarına kanıt eklenir.
- Üretilen `Finding` kayıtları uyum analizine aktarılır ve `analysis` kategorisinde kalite uyarıları olarak raporlanır.

## Test ve doğrulama

- `npm run test:adapters` komutu yalnızca adapter birim testlerini çalıştırır.
- Büyük dosya senaryoları için testler geçici olarak >5 MB boyutunda örnek dosyalar üretir ve dönüştürücülerin bellek dostu davranışını doğrular.
- Yanlış biçimlendirilmiş dosyalar beklenen hata mesajlarıyla reddedilir ve testler bu durumları denetler.

Akış tabanlı yaklaşım, CI ortamında büyük verileri içe aktarırken bellek taşmalarını önler ve kullanıcıya daha güçlü geri bildirim sağlar.
