# DO-178C Uyum Matrisi Veri Modeli

SOIPack, DO-178C Ek A hedeflerini değerlendirmek için kanıta dayalı bir uyum matrisi üretir. Bu belge, `@soipack/core` ve `@soipack/engine` paketlerinde bulunan temel veri yapılarını özetler.

## Objective kataloğu

`@soipack/core` paketi `packages/core/src/objectives.ts` dosyasında resmi DO-178C hedef kataloğunu tek bir kaynakta toplar.

- `objectiveCatalog`: Tüm hedeflerin doğrulanmış listesini içerir.
- `objectiveCatalogById`: Hedef kimliklerinden `Objective` kayıtlarına hızlı erişim sağlar.
- `getObjectivesForLevel(level)`: Belirli bir sertifikasyon seviyesinde uygulanabilir hedefleri döndürür. Opsiyonel `includeNotApplicable` parametresi tüm hedefleri düz bir liste olarak almak için kullanılabilir.
- `Objective` nesnesi her hedef için tablo (`A-3`…`A-7`), açıklama, beklenen artefakt türleri ve bağımsızlık gerekliliklerini içerir.

Katalog veri seti `data/objectives/do178c_objectives.min.json` dosyasından yüklenir ve `objectiveListSchema` ile doğrulanır. Böylece dış kaynaklı verinin bütünlüğü test sırasında korunur.

## ComplianceMatrix üreticisi

`@soipack/engine` paketinde yer alan `buildComplianceMatrix` fonksiyonu, hedef kataloğunu ve kanıt indeksini kullanarak seviyeye özel uyum raporu oluşturur.

```ts
interface ComplianceMatrix {
  level: CertificationLevel;
  tables: Array<{
    table: ObjectiveTable;
    objectives: Array<{
      objective: Objective;
      status: 'satisfied' | 'partial' | 'missing' | 'not-applicable';
      evidence: Array<{ type: ObjectiveArtifactType; items: Evidence[] }>;
      evidenceList: Evidence[];
      missingArtifacts: ObjectiveArtifactType[];
      warnings: string[];
    }>;
  }>;
  summary: {
    satisfied: number;
    partial: number;
    missing: number;
    notApplicable: number;
  };
  warnings: string[];
}
```

Fonksiyon her hedef için beklenen artefakt türlerini `EvidenceIndex` ile eşleştirir:

- Tüm gerekli artefaktlara kanıt atandıysa durum `satisfied` olur.
- Bazı artefaktlar eksikse durum `partial` olarak işaretlenir ve `missingArtifacts` alanı eksikleri listeler.
- Hiç kanıt yoksa durum `missing` olur.
- Seviye için geçerli olmayan hedefler `not-applicable` olarak raporlanır ve eksiklik listeleri boş döner.

Özet bölümünde her durum için sayaçlar tutulur. `warnings` listesi, eksik kanıt bulunan hedefleri kullanıcıya sunar ve aynı mesajlar tablo düzeyindeki girdilerde de saklanır.

## Veri akışı

1. Dış kaynaklardan gelen kanıtlar `EvidenceIndex` yapısına taşınır.
2. `objectiveCatalog` içindeki hedefler sertifikasyon seviyesine göre değerlendirilir.
3. `buildComplianceMatrix` çıktısı, raporlama ya da kullanıcı arayüzü katmanlarında görselleştirilmek üzere kullanılabilir.

Bu yaklaşım, uyum boşluklarını otomatik olarak saptayarak sertifikasyon hazırlığında tutarlı bir denetim izi sağlar.
