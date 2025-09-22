# SOIPack

SOIPack, yazılım odaklı organizasyonların gereksinim, test, kod ve kalite artefaktlarını bağlamak için tasarlanmış uçtan uca bir izlenebilirlik platformunun monorepo iskeletidir. Monorepo; çekirdek domain türleri, farklı artefakt bağdaştırıcıları, izlenebilirlik motoru, raporlama çıktıları, CLI ve REST API katmanlarını tek bir yerde toplar.

## Paketler

- **@soipack/core** – Gereksinim ve test domain şemaları, ortak türler.
- **@soipack/adapters** – Jira CSV, ReqIF, JUnit XML, LCOV/Cobertura, Polyspace, LDRA, VectorCAST ve Git gibi kaynaklardan veri bağdaştırıcılarının temel iskeleti.
- **@soipack/engine** – Hedef eşleme ve izlenebilirlik hesaplamalarını yöneten çekirdek motor.
- **@soipack/packager** – Manifest ve Ed25519 imzası ile veri paketleri oluşturan yardımcılar.
- **@soipack/report** – HTML/JSON rapor şablonları ve Playwright tabanlı PDF üretimi için yardımcılar.
- **@soipack/cli** – İzlenebilirlik işlemlerini otomatikleştiren komut satırı istemcisi.
- **@soipack/server** – Express ve OpenAPI tabanlı REST servisleri.

> Not: Sunucu yalnızca HTTPS dinleyicisiyle başlatılır; `SOIPACK_TLS_KEY_PATH` ve `SOIPACK_TLS_CERT_PATH` olmadan hizmet ayağa kalkmaz. Yönetici uç noktaları için istemci sertifikası doğrulaması isteğe bağlıdır (`SOIPACK_TLS_CLIENT_CA_PATH`). JWKS uç noktaları HTTPS ile çağrılmalı veya dosya sistemi üzerinden (`SOIPACK_AUTH_JWKS_PATH`) sağlanmalıdır. İstekler varsayılan olarak IP ve kiracı bazında sınırlandırılır (`SOIPACK_RATE_LIMIT_*`); JSON gövdeleri `SOIPACK_MAX_JSON_BODY_BYTES` eşiğini aşarsa `413` yanıtı döner.

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
     --git . \
     --project-name "SOIPack Demo Avionics" \
     --project-version "1.0.0" \
     --level C \
     --objectives data/objectives/do178c_objectives.min.json \
     -o .soipack/work
  ```

   Çalışma alanı çıktısı `workspace.json`, test sonuçlarına ek olarak `findings`
   (Polyspace/LDRA/VectorCAST bulguları) ve `structuralCoverage`
   (VectorCAST/LDRA kapsam özetleri) alanlarını içerir. Bu bilgiler ilgili
   hedeflere bağlanan kanıt kayıtlarıyla birlikte saklanır.

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

6. Dağıtım paketini hazırlayın:

   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key pack -i dist -o release --name soipack-demo.zip
   ```

7. Manifest imzasını doğrulayın:

   ```bash
   node packages/cli/dist/index.js verify \
     --manifest release/manifest.json \
     --signature release/manifest.sig \
     --public-key path/to/ed25519_public.pem
   ```

   Çıktı `Manifest imzası doğrulandı (ID: …)` şeklinde ise paket teslimat için hazırdır.

Tek komutla tüm adımların çalıştığı pipeline için örnek yapılandırmayı kullanabilirsiniz:

```bash
node packages/cli/dist/index.js --license data/licenses/demo-license.key run --config examples/minimal/soipack.config.yaml
```

Bu adımlar `examples/minimal` altındaki örnek verilerle birlikte çalışır. Aynı dizindeki `demo.sh` betiği, CLI derlemesini kontrol ederek pipeline komutunu otomatik olarak çalıştırır.

### Ed25519 Anahtar Üretimi

Paket manifestlerini imzalamak için bir Ed25519 anahtar çifti oluşturun:

```bash
openssl genpkey -algorithm Ed25519 -out ed25519_private.pem
```

İsteğe bağlı olarak kamu anahtarını çıkarmak için `openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem` komutunu kullanabilirsiniz.

## Lisans

Bu proje [MIT Lisansı](./LICENSE) ile lisanslanmıştır.
