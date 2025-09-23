# DO-178C Uçtan Uca Demo

Bu belge, DO-178C seviyesinde örnek bir kanıt setini kullanarak SOIPack CLI ile uçtan uca PoC akışının nasıl çalıştırılacağını
anlatır. Demo verileri küçük tutulmuştur; tüm işlem birkaç dakika içinde tamamlanabilir.

## Örnek Veri Kümesi

Aşağıdaki artefaktlar `data/samples/` dizininde sağlanır:

| Dosya | Açıklama |
| --- | --- |
| `jira-do178c.csv` | Jira CSV dışa aktarımı. Üç örnek görev, durumları ve etiketleri içerir. |
| `requirements-do178c.reqif` | İki gereksinim nesnesi içeren minimal ReqIF dokümanı. |
| `tests-do178c.xml` | JUnit XML raporu; her test ilgili gereksinim kimliğini `system-out` alanında referanslar. |
| `coverage-do178c.lcov` | LCOV kapsam raporu; autopilot modülü için örnek kapsama satırlarını içerir. |

Demo scripti ayrıca `data/objectives/do178c_objectives.min.json` hedef tablosunu ve varsayılan imza sertifikası
`test/certs/dev.pem` dosyasını kullanır.

## Adım Adım Akış

1. **İçe aktarım:** Jira, ReqIF, JUnit ve LCOV artefaktları `runImport` ile tek workspace’e yüklenir. Çıktı `workspace.json`
   dosyasında toplanır.
2. **Analiz:** `runAnalyze` gereksinim karşılama ve kapsam metriklerini hesaplar. Sonuçlar `analysis/` dizininde tutulur.
3. **Raporlama:** `runReport` HTML ve doküman çıktıları üretir; `dist/reports/` altında compliance, trace ve gap raporları oluşur.
4. **Paketleme:** `runPack` manifest dosyasını oluşturur, `test/certs/dev.pem` ile Ed25519 JWS imzası üretir ve `do178c-demo.zip`
   arşivini yaratır. İmzalama sonrası doğrulama başarısız olursa süreç durdurulur.

Tüm adımları otomatik olarak çalıştırmak için aşağıdaki komutu kullanın:

```bash
npm run demo:test
```

Komut, geçici çalışma dizinleri oluşturur, pipeline’ı çalıştırır ve manifest imzasını doğrular. Hata oluşursa ayrıntılı mesajla
sonlanır ve tüm geçici dizinler temizlenir.

### Manuel Kontroller

- `release/manifest.json` içeriğini gözden geçirerek `files` listesinin ve SHA-256 karmalarının oluşturulduğunu doğrulayın.
- `workspace.json` içindeki `evidenceIndex` kayıtlarının yerel artefaktlar için `hash`
  alanı taşıdığını ve değerlerin 64 karakterlik SHA-256 karmaları olduğunu kontrol edin.
- `manifest.sig` dosyasını `soipack verify --manifest ...` komutuyla doğrulayarak Ed25519 JWS imzasının geçerli olduğunu teyit
  edin.
- Oluşan `do178c-demo.zip` arşivinin içeriğinde raporlar ve manifest dosyalarının bulunduğunu kontrol edin.

Bu demo, gerçek verilerle aynı pipeline’ı kullanır; daha büyük veri kümeleri için dosyaları kendi gereksinim kayıtlarınızla
değiştirmeniz yeterlidir.
