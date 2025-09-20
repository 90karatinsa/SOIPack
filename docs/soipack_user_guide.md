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

### Pipeline'ı manuel çalıştırma
Aşağıdaki adımlar aynı çıktıları üretir ve kendi veri kümelerinizi kullanırken özelleştirilebilir:

1. **Örnek veriyi içe aktarın**
   ```bash
   node packages/cli/dist/index.js import \
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
2. **Uyum analizini hesaplayın**
   ```bash
   node packages/cli/dist/index.js analyze \
     -i .soipack/work \
     -o .soipack/out \
     --level C \
     --objectives data/objectives/do178c_objectives.min.json \
     --project-name "SOIPack Demo Avionics" \
     --project-version "1.0.0"
   ```
3. **Raporları üretin**
   ```bash
   node packages/cli/dist/index.js report -i .soipack/out -o dist/reports
   ```
4. **Dağıtım paketini oluşturun**
   ```bash
   node packages/cli/dist/index.js pack -i dist -o release --name soipack-demo.zip
   ```

Pipeline'ın YAML sürümü için `node packages/cli/dist/index.js run --config examples/minimal/soipack.config.yaml` komutunu çalıştırabilirsiniz; bu komut demo betiğinin tetiklediği konfigürasyonla aynıdır.【F:README.md†L36-L73】

### Raporları inceleme
Raporlar `dist/reports/` altında toplanır. `compliance_matrix.html` ve `trace_matrix.html` tarayıcıda açılarak müşteriye canlı demo yapılabilir; `compliance_matrix.pdf` aynı dizinde yer alır ve denetim arşivi için hazırdır.【F:docs/demo_script.md†L18-L25】 Paket arşivi, HTML/PDF raporlarını ve manifest dosyalarını `release/soi-pack-*.zip` içinde taşır.【F:docs/demo_script.md†L26-L31】

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
