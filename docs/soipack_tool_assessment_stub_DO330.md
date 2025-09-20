# SOIPack Tool Assessment Stub (DO-330)

Bu belge, SOIPack CLI pipeline'ının DO-330 kapsamında **kredi vermeyen destek aracı** (development support tool, no certification credit) olarak konumlandırılması için başlangıç iskeletini sunar. Amaç; müşteri denetimlerinde sunulacak izlenebilirlik çıktılarının nasıl üretildiğini ve hangi kontrollerle doğrulandığını şeffaf şekilde göstermek, ancak aracın sonuçlarına doğrudan sertifikasyon kredisi tahsis etmemektir.

## 1. Araç Tanımı
- **Adı**: SOIPack CLI Pipeline
- **Sürüm**: Depo etiketi veya `SOIPACK_COMMIT` ortam değişkeni üzerinden izlenir.【F:packages/cli/src/version.ts†L1-L18】
- **Fonksiyonel Kapsam**: Gereksinim, test ve kaynak kodu bağdaştırıcılardan içe aktarır; izlenebilirlik grafı oluşturur; `compliance_matrix.html`, `trace_matrix.html`, `gaps.html` ve `compliance_matrix.pdf` raporlarını üretir; manifest imzalı `release/soi-pack-*.zip` paketini oluşturur.【F:docs/demo_script.md†L18-L31】

## 2. Operasyonel Kullanım Senaryosu
- Araç, kalite ekibinin izlenebilirlik delillerini toplaması için kullanılır.
- Çalıştırma genellikle `scripts/make-demo.sh` veya eşdeğer YAML konfigürasyonuyla tetiklenen tek komutluk pipeline üzerinden yapılır.【F:docs/demo_script.md†L10-L31】【F:README.md†L36-L73】
- Sonuçlar müşteri incelemesi sırasında `dist/reports/` altındaki HTML/PDF dosyaları üzerinden sunulur ve paket manifesti denetçilerle paylaşılır.【F:docs/demo_script.md†L18-L31】

## 3. DO-330 Sınıflandırması
- **Araç Türü**: Development Support Tool (DO-330 §11.4).
- **TQL Önerisi**: TQL-5 (kredi vermeyen destek aracı). Gerekçe:
  - Araç, süreç çıktılarının derlenmesinde yardımcı olur; doğrudan ürün yazılımının doğrulanması veya onaylanması için tek kaynak olarak kullanılmaz.
  - `gaps.html` raporu, eksik kanıtları işaretler ancak düzeltici işlemler ayrı mühendislik süreçleriyle yönetilir.【F:docs/demo_script.md†L22-L23】
  - Paket manifesti (`manifest.json`/`manifest.sig`) doğrulaması, sonuçların manuel denetimini kolaylaştırır fakat sertifikasyon kredisi tanımlamaz.【F:docs/demo_script.md†L26-L31】

## 4. Güvence Argümanı
- **İzlenebilirlik doğrulaması**: `trace_matrix.html` gereksinim-test-kod bağlantılarını görselleştirir; doğrulama ekibi sonuçları manuel olarak çapraz kontrol eder.【F:docs/demo_script.md†L23-L24】
- **Uyum değerlendirmesi**: `compliance_matrix.html` ve `compliance_matrix.pdf`, DO-178C hedeflerinin sağlanma durumunu özetler; test kanıtı eksikse `gaps.html` uyarı sağlar.【F:docs/demo_script.md†L18-L25】
- **Tekrarlanabilirlik**: Pipeline komutları `README.md` içinde belgelenmiştir, böylece denetim sırasında aynı girişlerle tekrar çalıştırılabilir.【F:README.md†L36-L73】
- **Bütünlük**: `release/manifest.json` ve `manifest.sig` hash kontrolü sağlar; müşteri tarafı doğrulama prosedürü ile tamamlanmalıdır.【F:docs/demo_script.md†L26-L31】

## 5. Tool Qualification Plan (TQP) İskeleti
Bu bölüm, DO-330'a uygun tam TQP'nin taslağı olarak kullanılmak üzere başlıkları listeler. Her alt başlık daha sonra detaylandırılmalıdır.

1. **Giriş**
   - Amaç
   - Referans dokümanlar (`docs/architecture.md`, `docs/demo_script.md`, `docs/soipack_security.md`)
2. **Araç Tanımı**
   - Bileşenler (Adapters, Core, Engine, Report, CLI) ve veri akışı özeti.【F:docs/architecture.md†L1-L24】
   - Komut satırı arayüzü ve konfigürasyon dosyaları.
3. **TQL Belirleme**
   - DO-330 akışına göre kredi vermeyen destek aracının gerekçesi.
   - Kullanıcı rollerine göre sorumluluk matrisi.
4. **Niteliklendirme Stratejisi**
   - Manuel doğrulama prosedürleri (rapor incelemesi, manifest kontrolü).
   - Otomasyon destekleri (CI pipeline çıktıları, `demo_script` akışı).
5. **Test Planı**
   - Senaryo 1: Örnek veri seti ile demo pipeline (beklenen `release/soi-pack-*.zip`).
   - Senaryo 2: Eksik kanıt içeren veri seti → beklenen çıkış kodu `2` ve `gaps.html` uyarıları.【F:docs/demo_script.md†L22-L23】【F:packages/cli/src/index.ts†L116-L763】
6. **Konfigürasyon Yönetimi**
   - Versiyonlama (`SOIPACK_COMMIT`), paket hashleri ve manifest saklama politikası.
   - Lisans dosyası kontrolü (`verifyLicenseFile`) ve anahtar yönetimi özetine referans.【F:packages/cli/src/index.ts†L40-L115】【F:docs/soipack_security.md†L1-L64】
7. **Problem Raporlama ve Çözümü**
   - Hata kodu matrisi (`docs/soipack_user_guide.md`) ve olay kayıt prosedürü.
8. **Onay ve Dağıtım**
   - Air-gap dağıtım adımları, müşteri kabul kriterleri (`docs/soipack_acceptance_checklist.md`).

Bu iskelet, denetçilerle paylaşılacak nihai TQP dokümanının bölümlerini tanımlar ve demo çıktılarındaki artefaktlara referans vererek SOIPack'in izlenebilirlik sağlama rolünü açıklar.
