# Veri İçeri Aktarıcıları

SOIPack dış araçlardan gelen kalite verilerini `@soipack/adapters` paketindeki dönüştürücülerle işler. Bu belge, JUnit XML, LCOV ve ReqIF veri akışlarının yeni akış (streaming) temelli dönüştürücülerini özetler.

## Ortak yapı taşları

- **ParseResult**: Her dönüştürücü `{ data, warnings }` yapısını döndürür.
- **EvidenceIndex**: Dönüştürülen kayıtlar uyum matrisi ve raporlama katmanına kanıt olarak aktarılır.
- Yeni dönüştürücüler büyük dosyaları satır veya olay bazlı okuyarak bellek kullanımını sabit tutar.

## REST API içe aktarma hattı

CLI komutlarının yanı sıra aynı dönüştürücüler, REST API üzerinden uzaktan yürütülen içe aktarma
işlerinde de kullanılabilir. `POST /v1/import` uç noktası, multipart/form-data gövdesindeki dosyaların
yanında JSON olarak kodlanmış bir `connector` alanı kabul eder. Alanın yapısı aşağıdaki gibidir:

```json
{
  "connector": {
    "type": "polarion",
    "options": {
      "baseUrl": "https://polarion.example.com",
      "username": "qa-reader",
      "token": "<api-token>"
    }
  }
}
```

Birden çok dosya yüklerken JSON parçasını multipart isteğe aşağıdaki örnekteki gibi
ekleyebilirsiniz:

```bash
curl -X POST https://soipack.example.com/v1/import \
  -H 'Authorization: Bearer <JWT>' \
  -H 'X-SOIPACK-License: <lisans>' \
  -F "reqif=@spec.reqif" \
  -F "junit=@results.xml" \
  -F 'connector={"type":"polarion","options":{"baseUrl":"https://polarion.example.com","username":"qa-reader","token":"s3cr3t"}};type=application/json'
```

Sunucu yalnızca şemada tanımlanan seçenekleri işler; tüm anahtarlar trim edilerek tipleri normalize
edilir ve fazlalıklar atılır. Parola, token, `apiToken`, `clientSecret` gibi gizli alanlar kalıcı
`job.json` metaverisinde ve günlüklerde otomatik olarak "REDACTED" ile maskelenir. Ayrıca sanitized ve
gizli alanlardan arındırılmış seçenekler deterministik biçimde hash’lenerek bir parmak izi (fingerprint)
üretilir. Bu fingerprint hem iş karmasına (job hash) eklenir hem de aynı bağlayıcı seçenekleriyle
tekrarlanan isteklerin deduplikasyonuna olanak tanır; seçenekler değiştirildiğinde yeni bir fingerprint
hesaplanarak farklı bir iş kimliği üretilir.

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

## Jenkins REST API kapsamı

Dosya: `packages/adapters/src/jenkins.ts`

- `fetchJenkinsArtifacts(options)` Jenkins build ve test raporlarının yanı sıra LCOV/Cobertura kapsam
  artefaktlarını da indirir.
- `options.coverageArtifacts` dizisindeki her giriş `{ type: 'lcov' | 'cobertura', path, maxBytes? }`
  şeklindedir; `path` değeri Jenkins artefaktının göreli yolunu belirtir.
- İndirilen her kapsam dosyası `options.artifactsDir` altında aynı göreli yol hiyerarşisiyle saklanır,
  SHA-256 karması hesaplanır ve sonuç `coverage` metaverisinde raporlanır.
- LCOV dosyaları `parseLcovStream`, Cobertura XML'leri `importCobertura` ile akış halinde parse edilerek
  `CoverageReport` verileri (`totals`, `files`, `testMap`) döndürülür.
- Jenkins test raporu JSON uç noktaları varsayılan olarak 5 MiB (`maxReportBytes`) ile sınırlıdır; kapsam
  artefaktları için ayrı bir 10 MiB varsayılan (`maxCoverageArtifactBytes`) bulunur ve gerekirse her artefakt
  için `maxBytes` ile özelleştirilebilir.
- HTTP 429/503 yanıtları için geri alma süresi `Retry-After` üstbilgisine göre ayarlanır; indirmeler başarısız
  olduğunda kullanıcıya ayrıntılı uyarılar iletilir ve aşırı büyük dosyalar diskten silinir.

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
- CLI `import` komutu `--jama-url`, `--jama-project` ve `--jama-token` bayraklarıyla Jama REST API’sine bağlanır; çekilen gereksinim, test ve ilişki kayıtları çalışma alanına birleştirilir ve kanıt indeksine `source=jama` olarak kaydedilir.

### Jama ek dosyalarının indirilmesi

- Jama REST API’sinin döndürdüğü her gereksinim veya test için listelenen ekler, `runImport` sırasında aynı istekte toplanır ve `attachments/jama/<öğeKimliği>/<dosyaAdı>` klasörüne akış (stream) halinde yazılır.
- İndirmeler en fazla dört eş zamanlı istekle sınırlandırılır; bir ek okunamazsa veya API 2xx dışında durum döndürürse CLI günlüklerinde uyarı olarak raporlanır ve sorunlu dosya yoksayılır.
- Başarılı indirmeler SHA-256 karmaları hesaplanarak kanıt indeksine eklenir; `workspace.json` ile `analysis.json` dosyalarındaki metaveri toplam ek sayısını, bayt cinsinden boyutu ve her dosyanın göreli yolunu içerir.
- Paketleme (`pack`) aşamasında `attachments/` dizini manifest içinde listelenir; böylece SOI paketleri Jama eklerini ve bunlara ait karmaları içerir.

## Jira Cloud REST API entegrasyonu

- `fetchJiraArtifacts(options)` Jira Cloud REST API’sini sayfalayarak gereksinim ve test kayıtlarını, izlenebilirlik bağlantılarını ve ilişkilendirilmiş ekleri tek bir pakette toplar.
- Varsayılan JQL ifadeleri yalnızca ilgili proje için `Requirement`, `Story`, `Test` gibi türleri çeker; `requirementsJql` ve `testsJql` alanlarıyla özel JQL sorguları tanımlanabilir.
- Jira test kayıtları üzerindeki `issuelinks`, `requirementIds` gibi alanlar normalize edilerek `RemoteTraceLink` listesine `verifies/implements/satisfies` türleriyle dönüştürülür.
- CLI `import` komutu için yeni bayraklar:
  - `--jira-api-url` (zorunlu): Jira Cloud taban URL’si.
  - `--jira-api-project` (zorunlu): Proje anahtarı veya kimliği.
  - `--jira-api-email` ve `--jira-api-token`: REST API’ye erişim ve ek indirme yetkisi için gerekli kimlik bilgileri.
  - `--jira-api-requirements-jql`, `--jira-api-tests-jql`: Gereksinim ve test aramalarını özelleştirmek için.
  - `--jira-api-page-size`, `--jira-api-max-pages`, `--jira-api-timeout`: Sayfalama ve zaman aşımı parametrelerini ayarlar.
- CLI bu parametrelerle çağrıldığında REST API’den gelen gereksinim, test ve izlenebilirlik verilerini çalışma alanındaki mevcut kayıtlarla birleştirir; `trace` ve `test` kanıt indeksine `source=jiraCloud` olarak kaydeder.

### Jira Cloud eklerinin yerel kopyaları

- Jira Cloud’dan dönen her ek, `runImport` sırasında `attachments/jiraCloud/<ISSUE-KEY>/<dosyaAdı>` yoluna akış halinde indirilir. Dosya adları ve konu anahtarları güvenli biçimde sanitize edilerek dosya sistemi çakışmaları önlenir.
- İstekler eş zamanlı olarak en fazla dört bağlantıyla yürütülür. HTTP 2xx olmayan yanıtlar, indirme hataları veya SHA-256 karma uyuşmazlıkları CLI uyarısı olarak raporlanır ve ilgili ek göz ardı edilir.
- Jira eklerine erişim için `--jira-api-email` ve `--jira-api-token` ile sağlanan kimlik bilgilerinin ek indirme yetkisi olması gerekir; büyük dosyalar ağ süresini uzatacağından `--jira-api-timeout` değerini artırmanız önerilir.
- Başarıyla indirilen her dosyanın SHA-256 karması hesaplanır ve kanıt indeksindeki `attachments` metaverisine yazılır. Çalışma alanı ve paketleme çıktıları manifest içinde `attachments/` dizinini listeler, böylece SOI paketleri tüm Jira eklerini ve karmalarını içerir.

## Polarion REST API ilişkileri

- `fetchPolarionArtifacts(options)` artık yalnızca gereksinim, test ve build kayıtlarını değil, Polarion iş öğeleri arasındaki bağlantıları da toplar.
- API yanıtlarında yer alan `linkedWorkItems`, `linkedTests`, `requirementIds` gibi alanlar analiz edilerek gereksinim-test ilişkileri `RemoteTraceLink` listesine dönüştürülür; link rolü `implements` veya `verifies` türlerine haritalanır.
- Sayfalama sırasında alınan `HTTP 429` yanıtları için mevcut ETag önbelleği korunur ve maksimum geri deneme sonrasında bile önbellekteki veri kullanılabildiğinden veri kaybı yaşanmaz; kullanıcıya yalnızca tek seferlik bir uyarı mesajı gösterilir.
- CLI `import` komutu Polarion’dan dönen `relationships` listesini izlenebilirlik kanıtı olarak ekler ve çalışma alanına yeni bağlantılar ekleyerek `source=polarion` metaverisini ilişkilerin toplam sayısı ile günceller.
- Aynı API çağrısı, her iş öğesi (`work item`) için ekleri (attachments) REST uç noktalarından toplayarak `attachments` alanında SHA-256 karması, MIME türü ve bayt boyutuyla döndürür. İndirilen her ek ilgili iş öğesi kimliğiyle eşleştirilir.
- Varsayılan uç nokta şablonu `/polarion/api/v2/projects/:projectId/workitems/:workItemId/attachments` olup `attachmentsEndpoint` ile özelleştirilebilir; koleksiyon sayfa boyutu `attachmentsPageSize`, eşzamanlı istek sayısı ise `attachmentsConcurrency` ile sınırlandırılabilir.
- Her dosya indirmesi varsayılan olarak 25 MB (`maxAttachmentBytes`) ile sınırlandırılır. Dosya boyutu üst sınırı aşıldığında indirme kesilir ve kullanıcıya uyarı olarak raporlanır, kaynağın URL’si ve dosya adı korunarak manifestte eksik içerik fark edilir.
- Polarion indirme yanıtlarından gelen ETag üstbilgileri `If-None-Match` ile tekrar kullanılarak gereksiz veri transferi engellenir; 304 yanıtlarında önceki karma değerleri korunur. 2xx/4xx karışık sayfa yanıtlarında her başarısız sayfa için ayrıntılı uyarı mesajı üretilir.

## DOORS Next Generation OSLC

- CLI `import` komutu `--doors-url`, `--doors-project`, `--doors-username`,
  `--doors-password` ve/veya `--doors-token` bayraklarıyla DOORS Next
  proje alanına bağlanır. Token sağlanırsa OAuth bearer, aksi halde temel kimlik
  doğrulaması kullanılır; başarısız token denemeleri otomatik olarak parolaya
  düşer.
- `fetchDoorsNextArtifacts(options)` gereksinim, test ve tasarım kayıtlarını `/rm`
  koleksiyonundan sayfalar; `oslc.pageSize` ve `maxPages` parametreleri CLI’dan
  opsiyonel olarak (`--doors-page-size`, `--doors-max-pages`) ayarlanabilir.
  İstek zaman aşımı için `--doors-timeout` değeri kullanılabilir. Dönen paket gereksinimler, testler,
  tasarımlar ve ilişki bağlantılarını içerir.
- Adapter ETag önbelleğini (`etagCache`) CLI çalışma alanına yazar ve 304
  yanıtlarında veri transferini atlar. API oran sınırı veya kimlik doğrulama
  hataları alınırsa uyarılar `runImport` çıktısına aktarılır.
- İçe aktarılan kayıtlar çalışma alanındaki gereksinim/test/tasarım dizilerine
  birleştirilir, DO-178C `trace`/`test` kanıt indeksine `source=doorsNext`
  olarak kaydedilir ve ilişki bağlantıları izlenebilirlik matrislerine eklenir.
- DOORS Next ekleri `attachments/doorsNext/<artifactId>/<dosyaAdı>` dizinine
  indirilir; dosya adları ve kimlikler güvenli karakterlerle sanitize edilir.
  Her indirme sırasında SHA-256 karması hesaplanır, varsayılan olarak 25 MB
  sınırı uygulanır ve `Retry-After` başlığına göre otomatik yeniden denemeler
  yapılır. 401 yanıtlarında OAuth erişim tokenı yenilenir; token yenileme
  başarısız olursa adaptör temel kimlik doğrulamasına döner. Eklerin indirilebilmesi için
  DOORS Next proje alanında OSLC ek indirme yetkisi ve `/rm/.../attachments`
  uç noktalarına HTTPS erişimi gereklidir.

## DOORS Classic CSV dışa aktarımları

- `importDoorsClassicCsv(path)` fonksiyonu DXL CSV dışa aktarımlarını satır
  bazlı okuyarak `RemoteRequirementRecord` ve izlenebilirlik bağlantıları
  (parent-child ve `verifies`/`implements` ilişkileri) üretir. Latin-1 kodlu
  dosyalar otomatik olarak algılanır.
- CLI `import` komutu birden fazla modülü `aggregateImportBundle` ile
  birleştirir; `--doors-classic-reqs`, `--doors-classic-traces` ve
  `--doors-classic-tests` bayrakları aynı anda kullanılabilir. Gereksinim
  kimlikleri kaynaklar arasında yinelendiğinde ilk örnek korunur.
- Her dosya DO-178C `trace` kanıt indeksine `source=doorsClassic` olarak
  kaydedilir ve çalışma alanı metaverisinde modül sayısı ile toplam gereksinim
  bağlantıları raporlanır.
- Örnek kullanım:

  ```bash
  npx soipack import \
    --output workdir \
    --doors-classic-reqs exports/system-module.csv \
    --doors-classic-traces exports/trace-module.csv \
    --doors-classic-tests exports/test-module.csv
  ```

## QA denetim kayıtları

Dosya: `packages/adapters/src/qaLogs.ts`

- `importQaLogs(path)` fonksiyonu QA denetim imza CSV'lerini satır bazlı olarak işler.
- Gerekli sütunlar: `Objective` (veya `Objective ID`) ve `Status`. Opsiyonel sütunlar `Artifact`, `Reviewer`, `Completed At`, `Notes` olarak eşleştirilir.
- Durum değerleri `approved`/`pending`/`rejected` biçiminde normalize edilir; `APPROVED`, `Beklemede`, `Reddedildi`, `in-review` gibi farklı yazımlar aynı kanonik değere eşlenir. Bilinmeyen ifadeler `pending` olarak varsayılır ve uyarı mesajı üretilir.
- Her satır `qa_record` kanıt özeti üretir; boş satırlar atlanır, eksik sütunlar veya tanınmayan durumlar uyarı olarak döndürülür.
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
