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

> Not: Tüm CLI komutları lisans doğrulaması yapar. Örnek demo anahtarını `--license data/licenses/demo-license.key` argümanı ile ilettiğinizden emin olun.

1. **Örnek veriyi içe aktarın**
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
2. **Uyum analizini hesaplayın**
   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key analyze \
     -i .soipack/work \
     -o .soipack/out \
     --level C \
     --objectives data/objectives/do178c_objectives.min.json \
     --project-name "SOIPack Demo Avionics" \
     --project-version "1.0.0"
   ```
3. **Raporları üretin**
   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key report -i .soipack/out -o dist/reports
   ```
4. **Dağıtım paketini oluşturun**
   ```bash
   node packages/cli/dist/index.js --license data/licenses/demo-license.key pack -i dist -o release --name soipack-demo.zip
   ```

Pipeline'ın YAML sürümü için `node packages/cli/dist/index.js --license data/licenses/demo-license.key run --config examples/minimal/soipack.config.yaml` komutunu çalıştırabilirsiniz; bu komut demo betiğinin tetiklediği konfigürasyonla aynıdır.【F:README.md†L36-L73】

### Sunucu lisans doğrulaması
SOIPack API'si, gönderilen her iş isteğinin geçerli bir lisans ile yetkilendirilmesini bekler. Uygulama başlatılırken `SOIPACK_LICENSE_PUBLIC_KEY_PATH` ortam değişkeni üzerinden Ed25519 kamu anahtarının base64 kodlu dosyası belirtilmelidir. İstemciler aşağıdaki yöntemlerden biriyle lisans anahtarını iletmelidir:

- JSON tabanlı lisans dosyasını base64'e çevirip `X-SOIPACK-License` HTTP başlığına ekleyin. Örnek: ``cat license.key | base64`` çıktısını başlık değeri olarak kullanın.
- `/v1/import` uç noktasına çok parçalı form gönderirken `license` alanına lisans dosyasını ekleyin; diğer uç noktalar yalnızca başlık yöntemini kabul eder.

Geçersiz ya da süresi dolmuş lisanslar `402` durum kodu ve `LICENSE_INVALID` hata kodu ile reddedilir; lisans başlığı olmadan gönderilen isteklerde ise `401` durum kodu ve `LICENSE_REQUIRED` mesajı döner.

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
| `500` | `UNEXPECTED_ERROR` | HTTP taşıma limiti (`maxUploadSizeBytes`) aşılırsa yükleyici `File too large` hatasıyla isteği sonlandırır. |

Sunucu yanıtları her durumda `error.code`, `error.message` ve (varsa) `error.details` alanlarını içerir; istemciler bu alanları kullanarak UI bildirimlerini veya otomatik yeniden denemeleri tetikleyebilir.

### Raporları inceleme
Raporlar `dist/reports/` altında toplanır. `compliance_matrix.html` ve `trace_matrix.html` tarayıcıda açılarak müşteriye canlı demo yapılabilir; `compliance_matrix.pdf` aynı dizinde yer alır ve denetim arşivi için hazırdır.【F:docs/demo_script.md†L18-L25】 Paket arşivi, HTML/PDF raporlarını ve manifest dosyalarını `release/soi-pack-*.zip` içinde taşır.【F:docs/demo_script.md†L26-L31】

### Web arayüzü ile pipeline takibi

SOIPack, REST API üzerinden yürütülen işleri gözlemlemek için React tabanlı bir arayüz sunar. Arayüzü başlatmak için repoda aşağıdaki komutu uygulayın:

```bash
npm run ui
```

Varsayılan olarak UI, aynı origin üzerindeki `/v1` uç noktalarına istek yapar; farklı bir API adresi kullanıyorsanız `VITE_API_BASE_URL` ortam değişkenini `npm run ui` komutundan önce tanımlayabilirsiniz. Giriş ekranına JWT tokenınızı yazdığınızda import → analyze → report adımları sırasıyla tetiklenir, her işin kuyruk/durum bilgisi gerçek zamanlı olarak “Pipeline aşamaları” bölümünde güncellenir ve sunucudan dönen uyarılar çalıştırma günlüğünde yer alır. İşlem tamamlandığında uyum ve izlenebilirlik matrisleri API’den gelen JSON dosyalarına göre doldurulur; “Rapor paketini indir” butonu ise sunucuda üretilen `analysis.json`, `snapshot.json`, `traces.json` ve HTML raporlarını gerçek dosya içerikleriyle zip halinde indirir.

Arayüzdeki temel görünüm aşağıda özetlenmiştir:

![SOIPack UI pipeline görünümü](images/ui-pipeline.png)

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
