# Plan Şablonları ve PDF/DOCX Üretimi

SOIPack'in plan ve standart belgeleri `packages/report/templates/plans/` dizinindeki
Handlebars şablonları kullanılarak oluşturulur. Her plan tipi (`psac`, `sdp`, `svp`,
`scmp`, `sqap`, `sas`) aynı klasördeki `.hbs` dosyası üzerinden varsayılan içerik sağlar ve
`base.hbs` düzeni HTML görünümünü oluşturur. Bu yaklaşım sayesinde planlar için varsayılan
paragraflar projeye özel verilerle kolayca özelleştirilebilir.

Handlebars şablonları plan oluşturma sırasında DO-178C uyumluluk verileriyle
beslenir. Şablonlarda `paragraph` ve `join` yardımcıları kullanılarak HTML çıktısı
üretilir, içerik daha sonra hem DOCX hem de PDF formatlarına dönüştürülür. PDF
oluşturma işlemi `pdfmake` kütüphanesiyle gerçekleştirilir ve SOIPack sürümü,
manifest numarası, kapsam özetleri gibi meta veriler belgeye otomatik olarak eklenir.

## Konfigürasyon Dosyası

Plan üretim süreci JSON konfigürasyonu üzerinden çalışır. Dosya içerisinde
oluşturulacak planlar, kullanılacak fotoğraf ve gereksinim verileri ile çıktı
dizinleri tanımlanır.

```json
{
  "snapshot": "./snapshot.json",
  "objectives": "./objectives.json",
  "outputDir": "../plan-output",
  "manifestId": "MAN-TR-2024-0001",
  "level": "C",
  "generatedAt": "2024-02-01T12:00:00Z",
  "project": { "name": "Demo Avionics", "version": "1.0.0" },
  "plans": [
    { "id": "psac" },
    { "id": "sdp", "overrides": { "sections": { "introduction": "<p>CLI intro override.</p>" } } },
    { "id": "svp" },
    { "id": "scmp" },
    { "id": "sqap" },
    { "id": "sas" },
    {
      "id": "do330-ta",
      "overrides": {
        "sections": {
          "qualificationStrategy": "<p>Kritik araçlar için TQL-4 doğrulama izleri bağımsız olarak gözden geçirilir.</p>"
        }
      }
    }
  ]
}
```

Alanlar:

- **snapshot**: `ComplianceSnapshot` verilerini içeren JSON dosyasının yolu.
- **objectives**: (Opsiyonel) DO-178C hedef meta verilerini içeren JSON dosyası.
- **outputDir**: PDF/DOCX dosyalarının yazılacağı dizin.
- **manifestPath**: (Opsiyonel) Hash manifest dosyasının yolu. Belirtilmezse
  `plans-manifest.json` oluşturulur.
- **manifestId** ve **generatedAt**: Belgelerin üstbilgilerinde kullanılacak bilgiler.
- **project**, **level**: Planların başlık ve özetlerinde gösterilecek proje bilgileri.
- **plans**: Üretilecek planların listesi. Her öğede `id` değeri (`psac`, `sdp`, vb.)
  ve isteğe bağlı `overrides` alanları bulunabilir. Overrides ile `overview`,
  belirli bölüm içerikleri veya ekstra notlar HTML olarak sağlanabilir.
- `do330-ta` veya `sas` şablonları kullanıldığında ek bölüm içerikleri
  `overrides.sections` ile HTML olarak özelleştirilebilir.
- `do330-ta` şablonu kullanıldığında `toolAssessment` nesnesi ile araç
  nitelendirme sınıfları, doğrulama argümanları ve imza satırları yapılandırılabilir:

```json
{
  "snapshot": "./snapshot.json",
  "plans": [
    {
      "id": "do330-ta",
      "toolAssessment": {
        "summary": "Araç seti TQL-4 gereksinimlerini sağlamak üzere doğrulanmıştır.",
        "qualificationArguments": [
          "Regression paketi her sürümde referans sonuçlarla karşılaştırılıyor.",
          "Araç bağımlılıkları konteyner imajında sabitlendi."
        ],
        "environmentNotes": ["CI Runner Ubuntu 22.04", "VectorCAST 2023R1"],
        "tools": [
          {
            "id": "vectorcast",
            "name": "VectorCAST",
            "version": "2023R1",
            "vendor": "Vector Informatik",
            "toolClass": "TQL-4",
            "usage": "Yapısal kapsam birleştirme",
            "qualificationSummary": "Sürüm 5.2 referans veri setiyle kıyaslandı",
            "evidence": ["reports/vectorcast-validation.pdf"],
            "status": "Approved"
          }
        ],
        "signatures": [
          {
            "role": "Lead Compliance Manager",
            "name": "A. Inspector",
            "organization": "Safety Org",
            "date": "2024-05-01"
          }
        ]
      }
    }
  ]
}
```

Bu bilgiler DOCX ve PDF çıktılarında araç sınıfı tablolarını, doğrulama argüman
listelerini ve imza bloklarını oluşturur.

### SAS (Software Accomplishment Summary)

- Varsayılan şablon dosyası: `packages/report/templates/plans/sas.hbs`
- Bölüm kimlikleri: `executiveSummary`, `complianceStatus`,
  `verificationResults`, `configurationStatus`, `openItems`
- Override anahtarları: `overrides.sections.executiveSummary` vb. ile HTML blokları
  güncellenebilir.
- Üretilen dosya adları: `sas.docx`, `sas.pdf`
- Şablon; kapsanan/missing hedef sayıları, test sonuçları ve açık maddeler özetini otomatik olarak
  `renderPlanDocument` ve `renderPlanPdf` çıktılarında sunar.

## CLI Kullanımı

Konfigürasyon dosyası hazırlandıktan sonra planlar CLI üzerinden üretilebilir:

```bash
soipack generate-plans --config ./config/plans.json
```

Komut, belirtilen tüm planlar için hem DOCX hem de PDF dosyaları oluşturur ve
çıktıları konfigürasyonda verilen `outputDir` altında saklar. Üretilen dosyaların
SHA-256 özetleri aynı dizindeki `plans-manifest.json` içerisinde listelenir.

## Hash Manifesti

Komut çalıştırıldığında aşağıdaki örneğe benzer bir manifest dosyası yazılır:

```json
{
  "generatedAt": "2024-02-01T12:00:00Z",
  "plans": [
    {
      "id": "psac",
      "title": "Plan for Software Aspects of Certification (PSAC)",
      "outputs": [
        { "format": "pdf", "path": "psac.pdf", "sha256": "…" },
        { "format": "docx", "path": "psac.docx", "sha256": "…" }
      ]
    }
  ]
}
```

Manifest, paketleme veya teslimat süreçlerinde PDF ve DOCX çıktılarının bütünlüğünü
hızla doğrulamak için kullanılabilir. Hash değerleri üretim sırasında hesaplanır ve
CLI testleri, konfigürasyon örneğiyle tüm planların başarıyla oluşturulduğunu
kanıtlar.
