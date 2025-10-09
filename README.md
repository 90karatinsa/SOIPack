<!-- markdownlint-disable MD013 MD029 MD031 MD032 MD040 -->
# SOIPack

SOIPack, yazılım odaklı organizasyonların gereksinim, test, kod ve kalite artefaktlarını bağlamak için tasarlanmış uçtan uca bir izlenebilirlik platformunun monorepo iskeletidir. Monorepo; çekirdek domain türleri, farklı artefakt bağdaştırıcıları, izlenebilirlik motoru, raporlama çıktıları, CLI ve REST API katmanlarını tek bir yerde toplar.

## Paketler

- **@soipack/core** – Gereksinim ve test domain şemaları, ortak türler.
- **@soipack/adapters** – Jira CSV, ReqIF, JUnit XML, LCOV/Cobertura, Polyspace, LDRA, VectorCAST, Azure DevOps Boards/Test Plans ve Git gibi kaynaklardan veri bağdaştırıcılarının temel iskeleti.
- **@soipack/engine** – Hedef eşleme ve izlenebilirlik hesaplamalarını yöneten çekirdek motor.
- **@soipack/packager** – Manifest ve Ed25519 imzası ile veri paketleri oluşturan yardımcılar.
- **@soipack/report** – HTML/JSON rapor şablonları ve Playwright tabanlı PDF üretimi için yardımcılar.
- **@soipack/cli** – İzlenebilirlik işlemlerini otomatikleştiren komut satırı istemcisi.
- **@soipack/server** – Express ve OpenAPI tabanlı REST servisleri.

> Not: Sunucu yalnızca HTTPS dinleyicisiyle başlatılır; `SOIPACK_TLS_KEY_PATH` ve `SOIPACK_TLS_CERT_PATH` olmadan hizmet ayağa kalkmaz. Yönetici uç noktaları için istemci sertifikası doğrulaması isteğe bağlıdır (`SOIPACK_TLS_CLIENT_CA_PATH`). JWKS uç noktaları HTTPS ile çağrılmalı veya dosya sistemi üzerinden (`SOIPACK_AUTH_JWKS_PATH`) sağlanmalıdır. İstekler varsayılan olarak IP ve kiracı bazında sınırlandırılır (`SOIPACK_RATE_LIMIT_*`); JSON gövdeleri `SOIPACK_MAX_JSON_BODY_BYTES` eşiğini aşarsa `413` yanıtı döner. Sunucuyu kapatırken geçici yükleme dizinleri otomatik olarak temizlenir.

## Başlarken

```bash
npm install
```

### Geliştirme Komutları

| Komut                  | Açıklama                                   |
| ---------------------- | ------------------------------------------ |
| `npm run build`        | Tüm paketleri TypeScript ile derler.       |
| `npm run typecheck`    | Projeler için tip kontrolü gerçekleştirir. |
| `npm run lint`         | ESLint ile kod kalitesini denetler.        |
| `npm run test`         | Jest ile birim testlerini çalıştırır.      |
| `npm run format`       | Prettier ile biçimlendirme uygular.        |
| `npm run format:check` | Prettier biçimlendirmesini kontrol eder.   |

## 5 dakikada demo

CLI paketini derleyip minimal örnek verilerle uçtan uca bir paket oluşturmak için aşağıdaki adımları izleyin. Tüm komutlar depo kök dizininden çalıştırılmalıdır.

> Not: SOIPack CLI, demo lisansını doğrulamak için `--license` bayrağına ihtiyaç duyar. Depoyla birlikte gelen örnek anahtar `data/licenses/demo-license.key` yolunda bulunur.

1. CLI derlemesini hazırlayın:

   ```bash
   npm run --workspace @soipack/cli build
   ```

2. Hedef kataloğunu gözden geçirin (isteğe bağlı):

   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key objectives list --level C \
     --objectives data/objectives/do178c_objectives.min.json
   ```

   Bu komut, yeni DO-178C hedef kataloğunu seviye filtresiyle birlikte listeler.

3. Örnek artefaktları çalışma alanına aktarın:

   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key import \
     --jira examples/minimal/issues.csv \
     --reqif examples/minimal/spec.reqif \
     --junit examples/minimal/results.xml \
     --lcov examples/minimal/lcov.info \
     --cobertura examples/minimal/coverage.xml \
     --import polyspace=examples/minimal/polyspace/report.json \
     --import ldra=examples/minimal/ldra/tbvision.json \
     --import vectorcast=examples/minimal/vectorcast/coverage.json \
     --import plan=docs/system-plan.md \
     --import standard=docs/software-standard.txt \
     --import qa_record=records/qa-summary.csv \
     --qa records/qa/audit-log.csv \
     --git . \
     --project-name "SOIPack Demo Avionics" \
     --project-version "1.0.0" \
     --level C \
     --objectives data/objectives/do178c_objectives.min.json \
     -o .soipack/work
  ```

  Çalışma alanı çıktısı `workspace.json`, test sonuçlarına ek olarak `findings`
  (Polyspace/LDRA/VectorCAST bulguları) ve `structuralCoverage`
  (VectorCAST/LDRA kapsam özetleri) alanlarını içerir. `--import` bayrağı
  DO-178C artefakt türleriyle eşleştirilen plan, standart veya QA kayıtları gibi
  dosyaları doğrudan kanıt indeksine eklemenizi sağlar. `--qa` bayrağı ile
  sağlanan denetim imza CSV'leri satır bazlı QA kayıtlarına dönüştürülür ve A-7
  hedeflerini otomatik olarak kapatır. `--jira-defects` bayrağı ise Jira CSV
  dışa aktarımındaki `Issue Type` sütununda `Bug`/`Defect` olarak işaretlenen
  kayıtları `problem_report` kanıtı olarak ekler ve açık/kapanmış durum
  sayımlarını çalışma alanı metaverisine işler. Statik analiz `findings`
  girdileri uyumluluk analizinde otomatik olarak `analysis` kategorisinde kalite
  uyarılarına dönüştürülür. Bu bilgiler ilgili hedeflere bağlanan kanıt
  kayıtlarıyla birlikte saklanır ve analiz aşamasında önerilen iz
  bağlantılarıyla (trace suggestions) desteklenir.

   Polarion ve Jenkins entegrasyonları için CLI'ya ek bayraklar geçebilirsiniz.
   Örneğin Polarion gereksinimlerini ve test koşumlarını çekmek için `--polarion-url`,
   `--polarion-project`, isteğe bağlı olarak `--polarion-username`/`--polarion-token`
   ve gerekli uç nokta özelleştirmelerini ekleyin. Jenkins build ve test raporları
   için benzer şekilde `--jenkins-url`, `--jenkins-job`, opsiyonel `--jenkins-build`
   ile temel/Token kimlik doğrulama bilgilerini sağlayın. CLI bu kaynaklardan gelen
   gereksinim, test ve build verilerini çalışma alanına ekleyip kanıt indeksine
   `polarion` ve `jenkins` kaynaklı kayıtlar olarak işler.

4. Uyum analizini üretin:

   ```bash
  node packages/cli/dist/index.js --license data/licenses/demo-license.key analyze \
    -i .soipack/work \
    -o .soipack/out \
    --level C \
    --objectives data/objectives/do178c_objectives.min.json \
    --project-name "SOIPack Demo Avionics" \
    --project-version "1.0.0"
  ```

  Analiz çıktısı `analysis.json`, statik analizden gelen açık bulguları `qualityFindings`
  altında `analysis` kategorisinde listeler ve `traceSuggestions` alanında gereksinim →
  test/kod eşleşmeleri için öneriler sunar. Bu öneriler, uyumluluk raporlarında
  "Önerilen İz Bağlantıları" bölümü olarak görüntülenir ve izlenebilirlikte gözden
  geçirilmesi gereken bağlantıları vurgular.

5. Raporları oluşturun:

  ```bash
  node packages/cli/dist/index.js --license data/licenses/demo-license.key report -i .soipack/out -o dist/reports
  ```

   Komut `dist/reports` altında HTML/JSON çıktılarıyla birlikte `plans/` klasöründe PSAC, SDP, SVP, SCMP ve SQAP şablonlarını HTML, DOCX ve (Playwright Chromium paketi yüklüyse) PDF olarak üretir. PDF oluşturma sırasında Playwright ortamı hazır değilse işlem uyarı mesajıyla atlanır.

   Plan metinlerini özelleştirmek için `--plan-config` parametresine aşağıdaki gibi bir JSON dosyası verebilirsiniz:

   ```json
   {
     "psac": {
       "overview": "<p>Program otoritesi ile mutabık kalınan PSAC özeti.</p>",
       "sections": {
         "schedule": "<p>Milestone M4 sonrası DER onayı planlanmıştır.</p>"
       }
     },
     "svp": {
       "sections": {
         "testingStrategy": "<p>Haftalık regresyonlar donanım-in-the-loop ortamında koşulur.</p>"
       },
       "additionalNotes": "<p>SVP değişiklikleri kalite ekibi tarafından onaylanmalıdır.</p>"
     }
   }
   ```

6. Aynı süreci tek komutta çalıştırmak için `ingest` komutunu kullanabilirsiniz:

   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key ingest \
     --input examples/minimal \
     --output dist
   ```

   Komut, belirtilen girdi dizinindeki artefaktları içe aktarır, uyum analizi gerçekleştirir ve raporları `dist/reports` altına kaydeder. Çıktı özetinde toplam/karşılanan hedef sayıları ve kapsam yüzdeleri görüntülenir.

7. Manifest ve zip paketini tek adımda oluşturmak için `package` komutunu çalıştırın:

   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key package \
     --input examples/minimal \
     --output dist \
     --signing-key path/to/signing-key.pem \
     --package-name soi-pack.zip
   ```

   Bu komut, `ingest` adımlarını tekrar ederek raporları günceller, `manifest.json` ve `manifest.sig` dosyalarını üretir ve tüm kanıtları `dist/soi-pack.zip` arşivine sıkıştırır. Manifestte listelenen dosya karmaları ve imza, `verify` komutu ile doğrulanabilir.

   JSON anahtarları plan kimliklerini (`psac`, `sdp`, `svp`, `scmp`, `sqap`) temsil eder; her plan içinde `overview`, `sections` (plan şablonundaki bölüm kimlikleri) ve isteğe bağlı `additionalNotes` alanları HTML içeriği kabul eder.

Plan şablonlarını rapor akışından bağımsız üretmek istediğinizde `generate-plans` komutunu kullanabilirsiniz. Bu komut,
JSON konfigürasyonu okuyarak listedeki her plan için DOCX ve PDF çıktıları üretir ve oluşan karmaları `plans-manifest.json`
dosyasına yazar:

```bash
node packages/cli/dist/index.js generate-plans --config config/plans.json
```

Alanların ayrıntıları ve örnek bir konfigürasyon için [docs/plans.md](docs/plans.md) dosyasına göz atın.

Sunucu tarafında toplanan kanıtları dondurmak ve yeni yüklemeleri engellemek için `freeze` komutunu kullanabilirsiniz. Komut, API üzerinden `/v1/config/freeze` uç noktasına istek gönderir ve aktif snapshot kimliğini çıktıda gösterir:

```bash
node packages/cli/dist/index.js freeze \
  --api http://localhost:3000 \
  --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

Veri versiyonlama sürecinin tamamı, snapshot kimlik formatları ve freeze akışının ayrıntıları [docs/versioning.md](docs/versioning.md) belgesinde açıklanmaktadır.

6. Dağıtım paketini hazırlayın:

   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key pack -i dist -o release --name soipack-demo.zip
   ```

7. Manifest imzasını doğrulayın:

   ```bash
   node packages/cli/dist/index.js verify \
     --manifest release/manifest.json \
     --signature release/manifest.sig \
     --package release/soi-pack.zip \
     --public-key path/to/ed25519_public.pem
  ```

  Çıktı `Manifest imzası doğrulandı (ID: …)` şeklinde ise paket teslimat için hazırdır. PEM dosyası, Ed25519 kamu anahtarını veya imzalama sırasında kullanılan X.509 sertifikasını içerebilir. `--package` bayrağı, imzası doğrulanan manifestte listelenen her dosyanın ZIP arşivinde bulunup bulunmadığını ve SHA-256 karmalarının eşleştiğini de denetler; eksik ya da değiştirilmiş dosyalar CLI tarafından doğrulama hatası olarak raporlanır.

Tek komutla tüm adımların çalıştığı pipeline için örnek yapılandırmayı kullanabilirsiniz:

```bash
node packages/cli/dist/index.js --license data/licenses/demo-license.key run --config examples/minimal/soipack.config.yaml
```

Bu adımlar `examples/minimal` altındaki örnek verilerle birlikte çalışır. Aynı dizindeki `demo.sh` betiği, CLI derlemesini kontrol ederek pipeline komutunu otomatik olarak çalıştırır.

## Öne çıkan özellikler

- **Azure DevOps entegrasyonu** – Boards çalışma öğelerini, Test Plans koşturmalarını ve build meta verilerini tek komutla içe aktarın. CLI, kişisel erişim jetonunu (PAT) Basic kimlik doğrulamasıyla gönderir, ekleri SHA-256 karmasıyla önbelleğe alır ve throttling yanıtlarında yeniden dener.

  ```bash
  node packages/cli/dist/index.js --license <LICENSE> import \
    --azure-devops-organization avionics-rd \
    --azure-devops-project flight-controls \
    --azure-devops-test-plan-id 42 \
    --azure-devops-work-item-query "Select [System.Id] From WorkItems Where [System.TeamProject] = 'flight-controls'" \
    --azure-devops-personal-access-token $AZDO_PAT \
    -o .soipack/work
  ```

  Ekran görüntüsü: `docs/images/azure-devops-import.png`

- **Kanıt tazelik ısı haritası** – Uyum raporları, DO-178C aşamalarına ve yaş bantlarına göre bucket'lanmış kanıt sayımlarını tablo ve inline SVG gradyanıyla sunar. JSON çıktıları `analysis.staleEvidenceHeatmap` alanında aynı veriyi taşır.

  ```bash
  node packages/cli/dist/index.js --license <LICENSE> report -i .soipack/out -o dist/reports
  ```

  Ekran görüntüsü: `docs/images/stale-evidence-heatmap.png`

- **SLSA uyumlu attestation** – `soipack package` komutu, manifest ve SBOM karmalarını Ed25519 ile imzalayan `attestation.json` dosyasını zip arşiviyle birlikte üretir; `soipack verify` komutu hem manifest imzasını hem de JWS attestation yükünü doğrular.

  ```bash
  node packages/cli/dist/index.js --license <LICENSE> package -i .soipack/out -o release --attestation
  node packages/cli/dist/index.js --license <LICENSE> verify --input release --attestation
  ```

  Ekran görüntüsü: `docs/images/attestation-download.png`

### Ed25519 Anahtar Üretimi

Paket manifestlerini imzalamak için bir Ed25519 anahtar çifti oluşturun:

```bash
openssl genpkey -algorithm Ed25519 -out ed25519_private.pem
```

İsteğe bağlı olarak kamu anahtarını çıkarmak için `openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem` komutunu kullanabilirsiniz.

## Lisans

Bu proje [MIT Lisansı](./LICENSE) ile lisanslanmıştır.

## DO-178C Demo

DO-178C seviyesinde küçük bir veri seti ile uçtan uca süreci denemek için [DO-178C Uçtan Uca Demo](docs/DO-178C-demo.md)
rehberini izleyin. Belge, örnek artefaktların konumunu açıklar ve `npm run demo:test` komutuyla çalıştırılabilen bir duman testi
sunur.
