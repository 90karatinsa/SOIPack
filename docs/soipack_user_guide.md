<!-- markdownlint-disable MD013 MD022 MD029 MD031 MD032 MD040 -->
# SOIPack Kullanıcı Rehberi

SOIPack, gereksinim-test izlenebilirliği, uyumluluk raporlaması ve imzalı dağıtım paketleri oluşturmak üzere tasarlanmış bir komut satırı araç seti sunar. Bu rehber, depoyu klonladıktan sonra aracı devreye almak, örnek veriyle uçtan uca çalıştırmak ve tipik hata kodlarını anlamak için gerekli adımları özetler.

## Kurulum

1. **Önkoşullar**
   - Node.js 18 veya üzeri.
   - Git ile klonlanmış SOIPack deposu.
   - Opsiyonel: Paket manifestlerini imzalamak için OpenSSL 3.
2. **Bağımlılıkların yüklenmesi**
   ```bash
   npm install
   ```
   Bu komut, monorepodaki tüm paketler için bağımlılıkları indirir ve `packages/` altındaki çalışma alanlarını hazırlar.
3. **CLI derlemesi (isteğe bağlı)**
   ```bash
   npm run --workspace @soipack/cli build
   ```
   Demo akışında `scripts/make-demo.sh` derlemeyi otomatik yapar; manuel kullanım için CLI'nın `packages/cli/dist/` altında hazır olduğundan emin olun.

## Kullanım

### Tek komutla demo
`scripts/make-demo.sh`, örnek verileri izole çalışma alanına kopyalar, lisans doğrulaması yapar ve uçtan uca pipeline'ı tetikler. Komut tamamlandığında aşağıdaki artefaktlar oluşur:

- `dist/reports/compliance_matrix.html` – hedef-kanıt eşleşmelerini gösteren uyum matrisi.【F:docs/demo_script.md†L18-L22】
- `dist/reports/gaps.html` – eksik kanıtların kırmızı ile işaretlendiği boşluk raporu.【F:docs/demo_script.md†L22-L23】
- `dist/reports/trace_matrix.html` – gereksinim → test → kod zincirini takip eden izlenebilirlik matrisi.【F:docs/demo_script.md†L23-L24】
- `release/soi-pack-*.zip` – raporlar, manifest ve imzaları içeren paket arşivi.【F:docs/demo_script.md†L26-L31】
- `release/manifest.json` ve `release/manifest.sig` – paket bütünlüğünü denetlemek için kullanılan imzalı manifest çifti.【F:docs/demo_script.md†L29-L31】
- `release/manifest.cms` – CMS/PKCS#7 imzası; zincirli sertifika paketiyle birlikte harici araçlara sağlanır.
- `release/sbom.spdx.json` – manifestte referanslanan ve paket içeriğinin tamamını listeleyen SPDX 2.3 yazılım malzeme listesi.

### Pipeline'ı manuel çalıştırma
Aşağıdaki adımlar aynı çıktıları üretir ve kendi veri kümelerinizi kullanırken özelleştirilebilir:

> Not: Tüm CLI komutları lisans doğrulaması yapar. Örnek demo anahtarını `--license data/licenses/demo-license.key` argümanı ile ilettiğinizden emin olun.

1. **Hedef kataloğunu gözden geçirin (isteğe bağlı)**
   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key objectives list --level C \
     --objectives data/objectives/do178c_objectives.min.json
   ```
   DO-178C hedefleri tablo, seviye ve artefaktlara göre listelenir; `--level` bayrağı belirli sertifikasyon seviyelerini filtreler.

2. **Örnek veriyi içe aktarın**
   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key import \
     --jira examples/minimal/issues.csv \
     --reqif examples/minimal/spec.reqif \
     --junit examples/minimal/results.xml \
     --lcov examples/minimal/lcov.info \
     --cobertura examples/minimal/coverage.xml \
   --git . \
    --project-name "SOIPack Demo Avionics" \
    --project-version "1.0.0" \
    --level C \
    --objectives data/objectives/do178c_objectives.min.json \
    -o .soipack/work
  ```
  Polarion gereksinim/test kayıtlarını veya Jenkins build verisini otomatik
  almak için sırasıyla `--polarion-url --polarion-project` ve `--jenkins-url
  --jenkins-job` bayraklarını (gerekirse temel/Token kimlik bilgileriyle) ekleyin.
  CLI bu kaynaklardan gelen artefaktları çalışma alanına ve kanıt indeksine
  `polarion`/`jenkins` olarak işler. Polarion REST ekleri otomatik olarak
  `attachments/polarion/` dizinine indirilir, SHA-256 karmalarıyla birlikte
  `source=polarion` kanıt kaydı oluşturulur ve `analysis.json` içindeki
  `sources.polarion.attachments` alanı toplam ek sayısını ve bayt cinsinden
  boyutunu raporlar. `--independent-source polarion` gibi bayraklar kullanarak
  indirilen Polarion eklerini bağımsız kanıt olarak işaretleyebilirsiniz.
  Jenkins kapsam artefaktlarını indirmek için `--jenkins-artifacts-dir`
  bayrağıyla yerel indirme klasörünü belirtin, her LCOV/Cobertura dosyası
  için `--jenkins-coverage-artifact type=lcov,path=coverage/lcov.info`
  (veya `lcov:coverage/lcov.info@5242880` sözdizimiyle) bayrağını tekrarlayın
  ve varsayılan 10 MiB sınırını özelleştirmek için
  `--jenkins-coverage-max-bytes` değerini kullanın. CLI, indirilen her
  artefaktı SHA-256 karmasıyla birlikte kanıt indeksine `source=jenkins`
  olarak kaydeder ve kapsam/test haritalarını mevcut LCOV/Cobertura akışlarıyla
  birleştirir.
  Jira Cloud REST API’sinden gereksinim ve test çekmek için `--jira-api-url`,
  `--jira-api-project`, gerekiyorsa `--jira-api-email` ve `--jira-api-token`
  bayraklarını ekleyin; isteğe bağlı olarak `--jira-api-requirements-jql` ve
  `--jira-api-tests-jql` değerleriyle özel JQL sorguları tanımlayabilirsiniz.
  CLI, API’den dönen gereksinim/test kayıtlarını, ilişkilendirilmiş ekleri ve
  otomatik `verifies`/`implements` bağlantılarını çalışma alanına birleştirir
  ve kanıt indeksine `source=jiraCloud` olarak kaydeder.
  DOORS Next REST entegrasyonu da benzer şekilde gereksinim, test ve tasarım
  kayıtlarını içe aktarır; erişilebilen her ek dosyası
  `attachments/doorsNext/` altında kalıcı hale getirilir, SHA-256 karması ile
  kanıt indeksine `source=doorsNext` olarak eklenir ve `--independent-source
  doorsNext` gibi bayraklar kullanıldığında bağımsız kanıt olarak işaretlenir.
  Çalışma alanı metaverisi, indirilen DOORS Next eklerinin toplam sayısını ve
  boyutlarını raporlar; böylece hangi gereksinim artefaktlarının fiziksel
  dosyalarla desteklendiğini hızlıca doğrulayabilirsiniz.
  Tasarım doğrulama CSV dışa aktarımlarını `--design-csv` ile,
  Polyspace/LDRA/VectorCAST statik analiz arşivlerini sırasıyla `--polyspace`,
  `--ldra`, `--vectorcast` bayraklarıyla ve kalite denetim günlüklerini birden
  fazla `--qa` parametresi vererek ekleyebilirsiniz. Bu alanlar web arayüzünde
  ilgili dosya türleri seçildiğinde otomatik olarak sınıflandırılır.
  Azure DevOps Boards ve Test Plans kayıtlarını almak için `--azure-devops-organization`,
  `--azure-devops-project`, `--azure-devops-work-item-query`, `--azure-devops-test-plan-id`
  ve `--azure-devops-personal-access-token` bayraklarını ekleyin. CLI, PAT değerini
  HTTP Basic kimlik doğrulamasıyla gönderir, sayfalı REST uç noktalarını otomatik
  dolaşır ve ekleri `attachments/azureDevOps/` dizinine SHA-256 karmalarıyla indirir.
  Aynı karma daha önce indirildiyse dosya yeniden indirilmez; böylece throttling
  sınırları aşıldığında tekrar denemeler sırasında zaman kazanılır. Build özetleri
  `analysis.json` içindeki `sources.azureDevOps.builds` alanında listelenir.
  Bağımsız inceleme gereksinimleri için `--independent-source junit` veya
  `--independent-artifact analysis=reports/safety-analysis.pdf` gibi bayrakları
  ekleyerek belirli kanıt kayıtlarını bağımsız olarak işaretleyebilirsiniz;
  UI'daki "Bağımsızlık tercihleri" paneli aynı değerleri JSON olarak form verisine
  yazar ve API aracılığıyla CLI'nin bağımsızlık bayraklarına dönüştürür.
  aksi halde DO-178C’de bağımsızlık zorunlu olan hedefler analiz sırasında
  otomatik olarak boşluk olarak listelenir.
  CLI, yerel dosya sisteminden okunan her artefakt için kanıt kaydına
  SHA-256 `hash` değeri ekler; bu alan `workspace.json` içinde tutulur ve
  sonradan yeniden içe aktarımda tutarlılık kontrolü sağlar. `--import`
  bayrağı, DO-178C artefakt anahtarları (`plan`, `standard`, `qa_record` vb.)
  üzerinden manuel dosyaları kanıt indeksine eklerken `--qa` denetim imza
  CSV'lerini satır bazlı QA kayıtlarına dönüştürür. Yeni `--jira-defects`
  ve `--design-csv` bayrakları ise Jira CSV dosyalarındaki `Issue Type`
  sütununu ve tasarım tablolarındaki ilişki sütunlarını kullanarak ilgili
  `problem_report` ve `trace` kanıtlarını oluşturur, açık/kapanmış kayıt
  sayılarını çalışma alanı metaverisine yazar.
3. **Uyum analizini hesaplayın**
   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key analyze \
     -i .soipack/work \
     -o .soipack/out \
     --level C \
     --objectives data/objectives/do178c_objectives.min.json \
     --project-name "SOIPack Demo Avionics" \
     --project-version "1.0.0"
   ```

#### Değişiklik etkisi puanlaması

`analyze` komutu, önceki bir çalıştırmadan alınan `snapshot.json` dosyasını
`--baseline-snapshot <dosyaYolu>` argümanıyla kabul eder. CLI bu dosyayı JSON
olarak okuyup içindeki `traceGraph` düğümlerini doğrular; grafik eksikse veya
dosya okunamazsa aynı çalıştırmanın `analysis.json` çıktısına bir uyarı eklenir
ve değişiklik etkisi hesaplanmadan devam edilir. Başarılı durumlarda baseline
grafiği `generateComplianceSnapshot` çağrısına aktarılır, böylece güncel iz
grafiği ile kıyaslanarak değişiklik puanlaması yapılır ve sonuçlar hem
`snapshot.json` hem de `analysis.json` metaverisine yazılır.【F:packages/cli/src/index.ts†L4083-L4189】【F:packages/cli/src/index.test.ts†L1488-L1556】

##### Git referansından baseline yüklemek

Yerel dosya belirtmek yerine `--baseline-git-ref <etiket|dal|commit>` bayrağı
ile repodaki başka bir revizyondan snapshot okumak mümkündür. CLI, referansın
altındaki varsayılan `.soipack/out/snapshot.json` yolunu `git show <ref>:.soipack/out/snapshot.json`
komutuyla akış olarak çeker; özel bir yol gerekiyorsa her zaman
`--baseline-snapshot` bayrağı önceliklidir. Seçeneklerin tamamı için
[Kullanım](#kullanım) bölümündeki `analyze` komutu örneğini inceleyebilirsiniz.
Pipeline aynı girdilerle çalıştırıldığında kimliklendirilmiş revizyonları
`git tag -a soipack/baseline-<tarih>` gibi açıklamalı etiketlerle işaretlemek,
gelecekteki `--baseline-git-ref` çağrılarında tutarlı snapshot'lara dönmenizi
kolaylaştırır.【F:packages/cli/src/index.ts†L4107-L4184】【F:packages/cli/src/index.test.ts†L1589-L1718】

CLI, baseline kaynaklarını aşağıdaki sırayla değerlendirir:

1. `--baseline-snapshot` ile belirtilen yerel dosya.
2. `--baseline-git-ref` ile getirilen git snapshot'ı.
3. Önceki çıktılara erişilemezse baseline olmadan devam edilir.

Bu mekanizma, air-gapped ortamlarda `.soipack/out/snapshot.json` varsayılan
yolunun tar-ball veya paket arşivleriyle birlikte transfer edilmesini;
geliştirme kollarında ise `git fetch --tags` ile etiketlerin senkronize
edilmesini gerektirir.

###### Sık karşılaşılan git kaynaklı sorunlar

- **Detached HEAD üzerinde çalışmak:** CI sistemleri `HEAD` detached durumda
  olabilir; `--baseline-git-ref` için açıklamalı etiket veya doğrudan commit
  karması kullanın. `git show` referansı çözemediğinde CLI uyarı yazar ve
  baseline olmadan devam eder.
- **Sparse checkout kullanımı:** Depoda `git sparse-checkout` etkinse
  `.soipack/out/snapshot.json` yolunun sparse listesinde olduğundan emin olun;
  aksi halde `git show` boş içerik döndürebilir. Geçici olarak
  `git sparse-checkout add .soipack/out/snapshot.json` komutuyla erişimi
  genişletin.
- **Büyük snapshot dosyaları:** On binlerce düğüm içeren snapshot'lar git
  transferini yavaşlatabilir. Bu durumda baseline'ı yerelde saklayıp
  `--baseline-snapshot` ile paylaşın veya eski revizyonlarda yalnızca gerekli
  modülleri içeren hafifletilmiş snapshot'lar üretin.

Değişiklik etkisi skorları; düğümdeki doğrudan değişiklikler, gereksinim/test
kapsamı ve bağlantı ripple etkilerinin ağırlıklı toplamıyla (`base + coverage +
ripple`) hesaplanır. Analiz çıktısı dört durumdan (eklenen, kaldırılan,
güncellenen, etkilenen) birini içerir ve en yüksek şiddet değerine sahip ilk 25
kayıt azalan sırayla listelenir. Bu sonuçlar, aynı düğümün iz anahtarını ve
gerekçe özetini koruyarak raporlama katmanına aktarılır.【F:packages/engine/src/impact.ts†L41-L120】【F:packages/engine/src/impact.ts†L332-L360】【F:packages/engine/src/index.ts†L1194-L1270】

Baseline dosyaları tamamen belleğe alındığından, önceki `analyze` çalıştırmasından
alınmış ve yalnızca ilgili sürüme ait iz düğümlerini içeren snapshot'ları
kullanmanız önerilir. Çok büyük trace graph'ları (ör. on binlerce düğüm)
analiz süresini uzatabileceği için gerekiyorsa `jq` ile gereksiz düğümleri
temizleyebilir veya kapsamı azalan modüllerle sınırlayabilirsiniz. CLI uyarıları
“iz grafiği içermiyor” ya da “okunamadı” mesajları veriyorsa, baseline
dosyasının geçerli JSON olduğunu ve `traceGraph.nodes` alanının dolu olduğunu
doğrulayın; böylece değişiklik etkisi tablosu yeniden oluşturulur.【F:packages/cli/src/index.ts†L3257-L3286】【F:packages/cli/src/index.test.ts†L889-L936】

Üretilen değişiklik etkisi verileri; uyum raporundaki "Değişiklik Etki Analizi"
bölümüne, uyum özeti API yanıtındaki `changeImpact` alanına ve Dashboard'daki
"Değişiklik Etkisi" kartına aynen yansıtılır. Böylece mühendislik ekipleri hem
CI raporlarından hem de web arayüzünden aynı öncelikli değişiklik listesini
görüntüleyebilir.【F:packages/report/src/index.ts†L2915-L3211】【F:packages/server/src/index.ts†L3748-L3807】【F:packages/ui/src/pages/DashboardPage.tsx†L498-L590】
4. **Raporları üretin**
   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key report -i .soipack/out -o dist/reports
   ```
   Çalıştırmanın ardından `dist/reports` dizininde uyum/izlenebilirlik HTML'lerinin yanında `plans/` klasörü oluşur. Bu klasörde PSAC, SDP, SVP, SCMP ve SQAP belgelerinin her biri için `*.html` ve `*.docx` çıktıları yer alır; Playwright Chromium bağımlılıkları kuruluysa aynı içerikler `*.pdf` olarak da üretilir. Playwright ortamı hazır değilse CLI `analysis.json` içine rapor uyarısı ekler ve plan PDF'lerini atlar.

   Plan içeriklerini özelleştirmek için `--plan-config` parametresiyle HTML blokları içeren bir JSON dosyası verebilirsiniz. Örnek:

   ```json
   {
     "psac": {
       "overview": "<p>Program otoritesi ile mutabık kalınan PSAC özeti.</p>",
       "sections": {
         "schedule": "<p>Milestone M4 sonrası DER onayı planlanmıştır.</p>"
       }
     },
     "sqap": {
       "sections": {
         "metrics": "<p>Kalite ekibi haftalık olarak hedef kapsam yüzdelerini raporlar.</p>"
       },
       "additionalNotes": "<p>QA notları kalite portalında tutulur.</p>"
     }
   }
   ```

   Her anahtar plan kimliğini (`psac`, `sdp`, `svp`, `scmp`, `sqap`) temsil eder. Planlar içinde `overview` başlığı ve `sections` altındaki bölüm kimlikleri (`introduction`, `softwareLifecycle`, `testingStrategy` vb.) HTML içeriği kabul eder; `additionalNotes` alanı ek not bloğu oluşturur.
5. **Dağıtım paketini oluşturun**
  ```bash
  node packages/cli/dist/index.js --license data/licenses/demo-license.key pack \
    -i dist \
    -o release \
    --name soipack-demo.zip \
    --attestation \
    --cms-bundle data/certs/cms-test.pem \
    --pqc-key secrets/sphincs-private.key \
    --pqc-algorithm SPHINCS+-SHA2-128s
  ```

  `--cms-bundle` yerine `--cms-cert` + `--cms-key` (ve gerekiyorsa `--cms-chain`) parametreleri kullanılarak CMS imzası için
  ayrı sertifika ve anahtar dosyaları belirtilebilir. Komut tamamlandığında manifest ve imzaların yanında `release/sbom.spdx.json`
  dosyası yazılır; CLI hem SBOM yolunu hem de SHA-256 karmasını çıktıya ekler ve aynı değer manifestteki `sbom.digest` alanına
  işlenir.

  Post-kuantum imzalama için `--pqc-key` bayrağı SPHINCS+ özel anahtarının base64 kodlu dosyasını, `--pqc-algorithm` ise
  kullanılacak varyantı belirtir (örn. `SPHINCS+-SHAKE-192f`). Eğer anahtar çiftinin kamu kısmını ayrıca yönetiyorsanız
  `--pqc-public-key sphincs-public.key` ile base64 kodlu kamu anahtarını da iletebilirsiniz; belirtilmezse CLI özel anahtardan
  otomatik olarak türetir. Komut çıktısında logger, üretilen post-kuantum imza algoritmasını ve kamu anahtarını içeren
  metaveriyi raporlar ve `manifest.sig` dosyasının JWS başlığına SPHINCS+ imza segmenti eklenir.

6. **Manifest, attestation ve paket içeriğini doğrulayın**
  ```bash
  node packages/cli/dist/index.js verify \
    --manifest release/manifest.json \
    --signature release/manifest.sig \
    --package release/soipack-demo.zip \
    --attestation \
    --public-key data/certs/demo-signing.pub.pem \
    --sbom release/sbom.spdx.json
  ```
  Bu komut, Ed25519 imzasının geçerliliğini kontrol ederken `release/soipack-demo.zip` arşivindeki tüm dosyaların manifestteki SHA-256 karmalarıyla eşleştiğini ve SBOM dosyasının karmasının manifestteki `sbom.digest` değeriyle uyuştuğunu doğrular. Arşivden eksilen veya içeriği değiştirilmiş dosyalar ile SBOM tutarsızlıkları CLI tarafından ayrıntılı hatalarla raporlanır ve komut `verificationFailed` çıkış kodu ile sonlanır. SBOM dosyası paketin içinde de bulunuyorsa CLI, paket içindeki SBOM karmasını ayrıca raporlar. `--attestation` bayrağı etkinleştirildiğinde `attestation.json` JWS yükü açılır ve listedeki `subject` karmalarının hem manifest hem de SBOM dosyalarıyla eşleştiği doğrulanır.

  CMS imza doğrulaması için `@soipack/packager` kütüphanesindeki `verifyManifestSignatureDetailed` fonksiyonuna `cms.signaturePem`
  ve `cms.certificatePem` alanları verilerek `release/manifest.cms` dosyası kontrol edilebilir.

### Monte Carlo risk simülasyonu

`risk simulate`, kapsama ve test geçmişinden yararlanarak uyum regresyon olasılıklarını Monte Carlo yöntemi ile tahmin eder. Komut
aşağıdaki JSON yapısını bekler:

```json
{
  "coverageHistory": [
    { "timestamp": "2024-01-01T00:00:00Z", "covered": 820, "total": 1000 },
    { "timestamp": "2024-02-01T00:00:00Z", "covered": 860, "total": 1000 }
  ],
  "testHistory": [
    { "timestamp": "2024-01-01T00:00:00Z", "passed": 95, "failed": 5 },
    { "timestamp": "2024-02-01T00:00:00Z", "passed": 97, "failed": 3, "quarantined": 2 }
  ]
}
```

Kapsam kayıtları `covered` ve `total` sayılarını, test kayıtları ise geçmişteki `passed`/`failed` (isteğe bağlı `quarantined`) değerlerini içerir. JSON dosyası hazırlandıktan sonra komut şu şekilde çalıştırılabilir:

```bash
node packages/cli/dist/index.js --license data/licenses/demo-license.key risk simulate \
  --metrics metrics/risk.json --iterations 2000 --seed 1337 --coverage-lift 4 --output dist/risk.json
```

`--iterations` Monte Carlo döngülerinin sayısını (1-10 000 arası) belirlerken `--seed` aynı dağılımları tekrar üretmek için deterministik tohum sağlar. `--coverage-lift` argümanı, en güncel kapsama gözlemine yüzde puan olarak iyileştirme veya düşüş uygulayarak “ne olurdu” senaryolarını test etmeyi sağlar; değer pozitif/negatif olabilir ancak sonuç 0-100 aralığına sıkıştırılır. Komut varsayılan olarak okunabilir bir tablo yazar, `--json` veya `--output` bayrakları ise simülasyon özetini ham JSON olarak yazdırır ya da dosyaya kaydeder.【F:packages/cli/src/index.ts†L3275-L3493】【F:packages/cli/src/index.ts†L5984-L6100】

### Paket artefaktlarını indirme

Pipeline sunucusu tarafından üretilen arşiv ve manifest dosyalarını almak için `download` alt komutu kullanılabilir:

```bash
node packages/cli/dist/index.js --license data/licenses/demo-license.key download \
  --api https://soipack.example.com \
  --token $TOKEN \
  --package $PACKAGE_ID \
  --output artifacts/
```

İndirilecek URL'ler varsayılan olarak HTTPS olmak zorundadır; CLI, `http://` taban adresleri güvenli olmadığı için reddeder. Yalnızca yerel geliştirme ortamlarında gerekli olduğunda `--allow-insecure-http` bayrağını global argüman olarak ekleyerek HTTP'ye geçici olarak izin verebilirsiniz.

Pipeline'ın YAML sürümü için `node packages/cli/dist/index.js --license data/licenses/demo-license.key run --config examples/minimal/soipack.config.yaml` komutunu çalıştırabilirsiniz; bu komut demo betiğinin tetiklediği konfigürasyonla aynıdır.【F:README.md†L36-L73】

### Sunucu lisans doğrulaması
SOIPack API'si, gönderilen her iş isteğinin geçerli bir lisans ile yetkilendirilmesini bekler. Uygulama başlatılırken `SOIPACK_LICENSE_PUBLIC_KEY_PATH` ortam değişkeni üzerinden Ed25519 kamu anahtarının base64 kodlu dosyası belirtilmelidir. İstemciler aşağıdaki yöntemlerden biriyle lisans anahtarını iletmelidir:

- JSON tabanlı lisans dosyasını base64'e çevirip `X-SOIPACK-License` HTTP başlığına ekleyin. Örnek: ``cat license.key | base64`` çıktısını başlık değeri olarak kullanın.
- `/v1/import` uç noktasına çok parçalı form gönderirken `license` alanına lisans dosyasını ekleyin; diğer uç noktalar yalnızca başlık yöntemini kabul eder.

Sunucu, her istekte lisansın son kullanma tarihini doğrular; önbellekte tutulan lisanslar süresi dolduğunda otomatik olarak temizlenir.
Geçersiz ya da süresi dolmuş lisanslar `402` durum kodu ve `LICENSE_INVALID` hata kodu ile reddedilir; lisans başlığı olmadan gönderilen isteklerde ise `401` durum kodu ve `LICENSE_REQUIRED` mesajı döner.

Pipeline uç noktaları ayrıca lisansın yetkilendirdiği özelliklere göre sınırlandırılır:

| Uç nokta | Gerekli özellik |
| --- | --- |
| `/v1/import` | `import` |
| `/v1/analyze` | `analyze` |
| `/v1/report` | `report` |
| `/v1/pack` | `pack` |

İlgili özellikler lisansın `features` alanında yer almıyorsa API `403 LICENSE_FEATURE_REQUIRED` döndürür ve `error.details.requiredFeature` alanında beklenen özelliği bildirir.

#### Sunucu API hata kodları

REST API, kimlik doğrulama ve kuyruk/depolama katmanında karşılaşılabilecek durumlar için yapılandırılmış hata gövdeleri döndürür. Sık görülen kodların özeti aşağıdadır:

| HTTP | Kod | Tipik Senaryo |
| ---- | --- | ------------- |
| `401` | `UNAUTHORIZED` | `Authorization` başlığı eksik veya JWT imzası/geçerliliği doğrulanamadı. |
| `401` | `LICENSE_REQUIRED` | `X-SOIPACK-License` başlığı olmadan `import`/`analyze`/`report`/`pack` uç noktalarına istek gönderildi. |
| `402` | `LICENSE_INVALID` | Lisans imzası bozuk, süresi dolmuş veya beklenen tenant ile eşleşmiyor. |
| `403` | `INSUFFICIENT_SCOPE` | JWT token gerekli kapsamı (`soipack.api`) içermiyor. |
| `400` | `NO_INPUT_FILES` | `/v1/import` isteği hiçbir dosya içermiyor; kuyruk işi oluşturulamıyor. |
| `400` | `INVALID_REQUEST` | Zorunlu alan (`importId`, `analysisId`, `reportId`) eksik veya parametre biçimi hatalı. |
| `400` | `INVALID_PATH` | Rapor varlığı indirilirken dizin dışına çıkmaya çalışan (ör. `../`) yol kullanıldı. |
| `404` | `JOB_NOT_FOUND` | İstenen iş kimliği mevcut değil veya başka bir tenant tarafından oluşturuldu. |
| `413` | `FILE_TOO_LARGE` | Alan bazlı politika (`uploadPolicies`) sınırı aşan dosya tespit edildi. |
| `429` | `QUEUE_LIMIT_EXCEEDED` | Kiracı başına veya global iş kuyruğu limiti aşıldı; `error.details.scope` hangi sınırın (`tenant`/`global`) tetiklendiğini belirtir. |
| `500` | `UNEXPECTED_ERROR` | HTTP taşıma limiti (`maxUploadSizeBytes`) aşılırsa yükleyici `File too large` hatasıyla isteği sonlandırır. |

Sunucu yanıtları her durumda `error.code`, `error.message` ve (varsa) `error.details` alanlarını içerir; istemciler bu alanları kullanarak UI bildirimlerini veya otomatik yeniden denemeleri tetikleyebilir.

### Raporları inceleme
Raporlar `dist/reports/` altında toplanır. Uyum (`compliance.html`/`compliance.json`), izlenebilirlik (`trace.html`) ve boşluk (`gaps.html`) çıktıları tarayıcıda açılarak inceleme yapılabilir; aynı klasörde `analysis.json`, `snapshot.json` ve `traces.json` çalışma zamanı verileri yer alır. `plans/` alt dizini ise PSAC, SDP, SVP, SCMP ve SQAP belgelerinin HTML/DOCX sürümlerini barındırır; Playwright Chromium mevcutsa aynı adlarla PDF kopyaları da oluşturulur. Pipeline paketleri bu dosyaları ve manifesti `release/soi-pack-*.zip` arşivine dahil eder.【F:docs/demo_script.md†L18-L31】

Uyum matrisi artık yapısal kapsam metriklerini Satır/Dallanma/Fonksiyon değerlerinin yanında MC/DC yüzdeleriyle birlikte gösterir. Gereksinimlere ait kod izleri bu dört metriği toplu olarak hesaplar; `MC/DC: %` etiketi tüm raporlarda otomatik görünür. Aynı matriste yeni “Kalite Bulguları” bloğu yer alır. Bu bölüm, doğrulandı olarak işaretlenmiş ama teste izlenmemiş gereksinimler, başarısız doğrulama testleri, eksik kapsam veya statik analiz araçlarının raporladığı açık bulgular gibi çelişkileri listeler. Kritik (hata) ve uyarı seviyeleri farklı rozet renkleriyle vurgulanır; her bulgu ilgili gereksinim, etkilediği test kimlikleri ve önerilen düzeltici aksiyon ile birlikte sunulur.

Statik analiz raporlarını CLI'ya `--polyspace`, `--ldra` ve `--vectorcast` bayraklarıyla aktarabilirsiniz. SOIPack bu dosyaları işlediğinde araçların bulduğu `error`/`warning` bulgularını `analysis` kategorisinde raporlar, toplam bulgu sayısını çalışma alanı metaverisine ekler ve `problem_report` kanıtı olarak kaydeder. LDRA ve VectorCAST çıktıları aynı zamanda yapısal kapsam metriklerini güncellerken, Polyspace çıktıları doğrulama kayıtlarını `review` kanıtı olarak zenginleştirir.

`analysis.json` çıktısı bu bulguları programatik olarak tüketebilmek için `qualityFindings` dizisini içerir. Dizideki her öğe; `severity` (error/warn/info), `category` (trace/tests/coverage/analysis), `message`, `requirementId`, `relatedTests` ve `recommendation` alanlarını taşır. CI/CD iş akışlarında bu alanları kullanarak örneğin doğrulandı durumda olup teste bağlanmamış gereksinimler veya kapatılmamış statik analiz uyarıları için pipeline'ı başarısız sayabilir ya da otomatik JIRA görevleri açabilirsiniz. Bir bulgu raporda belirdiyse, ilgili gereksinim durumunu gözden geçirmek, eksik test izlerini eklemek, kapsam raporlarını güncellemek veya statik analiz bulgusunu kapatmak önerilir.

SOIPack analiz adımı ayrıca gereksinimler ile testler/kod dosyaları arasında tutarlı kimlikler ve anahtar kelimeler arayarak yeni iz bağlantıları önerir. `analysis.json` içindeki `traceSuggestions` dizisi, her öneri için hedef kimliği, güven seviyesi ve önerinin gerekçesini bildirir. `trace.html` raporu “Önerilen İz Bağlantıları” bölümünde bu kayıtları göstererek gözden geçirenlerin hızlıca onaylayabileceği veya reddedebileceği bir kontrol listesi sunar.

### Web arayüzü ile pipeline takibi

SOIPack, REST API üzerinden yürütülen işleri gözlemlemek için React tabanlı bir arayüz sunar. Arayüzü başlatmak için repoda aşağıdaki komutu uygulayın:

```bash
npm run ui
```

Varsayılan olarak UI, aynı origin üzerindeki `/v1` uç noktalarına istek yapar; farklı bir API adresi kullanıyorsanız `VITE_API_BASE_URL` ortam değişkenini `npm run ui` komutundan önce tanımlayabilirsiniz. Giriş ekranına JWT tokenınızı yazdığınızda import → analyze → report adımları sırasıyla tetiklenir, her işin kuyruk/durum bilgisi gerçek zamanlı olarak “Pipeline aşamaları” bölümünde güncellenir ve sunucudan dönen uyarılar çalıştırma günlüğünde yer alır. İşlem tamamlandığında uyum ve izlenebilirlik matrisleri API’den gelen JSON dosyalarına göre doldurulur; “Rapor paketini indir” butonu ise sunucuda üretilen `analysis.json`, `snapshot.json`, `traces.json` ve HTML raporlarını gerçek dosya içerikleriyle zip halinde indirir.

UI derlemesi Vite'in `import.meta.env` nesnesini doğrudan kullanır ve dinamik `eval`/`new Function` çağrılarına ihtiyaç duymaz; bu sayede uygulama `Content-Security-Policy: script-src 'self'` gibi sıkı politika başlıklarıyla dağıtıldığında tarayıcılar tarafından engellenmez.

Token kutusunun hemen yanında yeni “Lisans Anahtarı” bileşeni bulunur. JSON tabanlı lisans dosyanızı yüklediğinizde veya panodan yapıştırdığınızda içerik istemci tarafında doğrulanır, `JSON.stringify` ile normalize edilir ve otomatik olarak base64’e çevrilerek tüm API çağrılarında `X-SOIPACK-License` başlığına eklenir. Lisans alanı boş bırakılırsa UI pipeline’ı başlatmadan önce uyarı gösterir ve sunucuya istek göndermez; bu sayede lisanssız isteklerin msw tabanlı testlerde bile `LICENSE_REQUIRED` hatasıyla reddedildiği doğrulanır.

“Risk kokpiti” sekmesi, sunucunun SSE kanalı üzerinden yayınladığı `riskProfile`, `ledgerEntry` ve yeni `manifestProof` olaylarını dinleyerek canlı sonuçları gösterir. Monte Carlo simülasyonlarıyla gelen aşama risk tahminleri, yüzde 10/50/90 bantlarını dolduran eğriler ve zaman içindeki sınıflandırma geçişleriyle görselleştirilir; böylece regresyon olasılığının nasıl evrildiği hızlıca okunabilir. Merkle kanıt gezgini kartı, gelen manifest kimliğini, Merkle kökünü ve dosya başına kanıt/ doğrulama durumlarını listeler; kanıtı bulunan dosyalar seçildiğinde `simulateComplianceRisk` çıktılarının da beslendiği risk paneliyle birlikte kanıt yolundaki her düğümün yön/hash bilgisi görselleştirilir. Seçili kanıt istekle alınırken hata oluşursa kart hata mesajını ve “Yeniden dene” butonunu gösterir; yeni olaylar geldiğinde durum rozeti, kanıt doğrulaması ve özet metaveriler otomatik güncellenir. What-if “Risk Sandbox” kartındaki hazır ayarlar, kapsam artışı/başarısızlık varsayımlarını tek tıkla günceller; özet, dağılım ve sınıf listeleri üzerine eklenen ipuçları her metriğin anlamını netleştirir.【F:packages/ui/src/pages/RiskCockpitPage.tsx†L1-L600】【F:packages/engine/src/risk.ts†L1-L270】

Arayüzdeki temel görünüm aşağıda özetlenmiştir:

![SOIPack UI pipeline görünümü](images/ui-pipeline.png)

#### Gereksinim Editörü

`Requirements Editor` sekmesi, çalışma alanı belgelerini API üzerinden doğrudan düzenlemenizi sağlar. Sayfaya token ve lisans bilgileriyle eriştiğinizde uygulama `/v1/workspaces/{workspaceId}/documents/{documentId}` uç noktasından en son revizyonu, yorumları ve imza isteklerini çeker. Revizyon ızgarasında her satır bir gereksinimi temsil eder; kimlik, başlık, açıklama, durum ve etiketler alanları hücre içinde düzenlenebilir. `Add requirement` düğmesi boş bir satır ekler.

Değişiklikler kaydedildiğinde istemci, beklenen karma değerini (`expectedHash`) mevcut revizyon hash'iyle doldurarak `PUT /v1/workspaces/{workspaceId}/documents/{documentId}` çağrısı yapar. Sunucu yeni revizyonu dönerse hash otomatik güncellenir ve ızgara temizlenir; aksi halde çakışma uyarısı görüntülenir. Sayfanın sağındaki yorum paneli, revizyonla ilişkili geribildirimleri listeler ve `Add comment` alanı yeni notların aynı revizyona eklenmesini sağlar.

İmza süreci için `Request signoff` düğmesi modal açar. Bu pencerede hedef rolü veya kullanıcı kimliğini girerek `POST /v1/workspaces/{workspaceId}/signoffs` çağrısını tetikleyebilir, sonuç olarak dönen kayıt hemen listelenen imza geçmişine eklenir. Onay süreci tamamlandığında signoff kartındaki durum etiketi güncellenir; böylece gereksinim setinin hangi revizyonunun denetimden geçtiği arayüzden izlenebilir.

#### RBAC Kullanıcı Yönetimi

`Yönetici Kullanıcılar` sekmesi yalnızca `admin` rolüne sahip oturumlarda görünür ve tüm çağrılar için token ile lisans anahtarının girilmiş olmasını zorunlu kılar. Sekmeye ilk kez girildiğinde istemci `GET /v1/admin/roles` ve `GET /v1/admin/users` çağrılarını birlikte çalıştırarak mevcut rol tanımlarını ve kullanıcı listesini önbelleğe alır; kimlik doğrulama eksikse arayüz bunu uyarı kartı ile bildirir ve istekleri tekrar denemez.

`Yeni Kullanıcı` eylemi e-posta, görünen ad ve rol seçimi için bir form açar. Kaydetme işlemi `POST /v1/admin/users` uç noktasına yönlendirilir ve sunucu geçici parola dönerse bu bilgi modal kapandıktan sonra “Güncelleme tamamlandı” alert bileşeninde gösterilir. Mevcut bir kaydı `Düzenle` bağlantısıyla açtığınızda form alanları ilgili kullanıcı verileriyle doldurulur; gönderim `PUT /v1/admin/users/{userId}` çağrısıyla rol atamalarını günceller. Güncellenen kullanıcıya ait doğrulama sırrı rota içerisinde dönerse arayüz hemen aynı alert bileşeniyle yeni sırrı yayınlar.

Her kullanıcı satırındaki `Sır Sıfırla` işlemi, söz konusu hesabın erişim anahtarını `rotateSecret: true` parametresiyle sıfırlar ve dönen yeni sırrı operatörle paylaşır. `Sil` butonu `DELETE /v1/admin/users/{userId}` çağrısını tetikler; işlem başarılı olduğunda satır hemen tablodan kaldırılır. Tüm aksiyonlar msw tabanlı testlerde sahte sunucu yanıtlarıyla doğrulanır ve `ApiError` istisnaları formun altındaki hata panelinde görüntülenerek operatöre gerekli düzeltme adımlarını iletir.

## Hata Kodları
SOIPack CLI süreçleri başarı ve başarısızlık durumlarını aşağıdaki çıkış kodlarıyla bildirir:

| Kod | Tanım | Tipik Senaryo |
| --- | ----- | ------------- |
| `0` | Başarılı tamamlandı | Tüm adımlar hatasız tamamlandı; raporlar `dist/reports/` altında oluştu. |
| `2` | Eksik kanıt bulundu | `gaps.html` raporu kırmızı satırlar içerir ve pipeline kritik kanıt eksiklikleri nedeniyle uyarıyla sonlanır. Paket yine de oluşturulur ancak kabul sürecinde inceleme gerektirir. |
| `3` | Genel hata | Lisans doğrulaması başarısız oldu, giriş dosyaları okunamadı veya analiz sırasında beklenmeyen bir istisna oluştu. Terminal log'unda hata açıklaması görünür; pipeline `release/soi-pack-*.zip` dosyasını üretmez. |

CLI'nin belirli alt komutları (`import`, `analyze`, `report`, `pack`, `run`) exit kodlarını `process.exitCode` aracılığıyla raporlar; kombine pipeline çalıştırıldığında ilk hata kodu `scripts/make-demo.sh` betiği tarafından terminalde yansıtılır.【F:packages/cli/src/index.ts†L116-L1140】

## Ek Kaynaklar
- `docs/demo_script.md`: Satış öncesi sunumlarda kullanılabilecek 5 dakikalık anlatım senaryosu.
- `docs/architecture.md`: Paketler arası veri akışını açıklayan genel mimari şema.
- `docs/deploy.md`: Üretim ortamı dağıtım önerileri.
