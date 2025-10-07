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

## Regülasyon çapraz referansları

Uyum matrisi, her hedef satırında ilgili düzenleyici rehberliği gösterebilmek için bir çapraz referans kataloğu kullanır. `@soipack/report` paketi, DO-178C Ek A tablolarını hem FAA danışma materyalleriyle hem de EASA AMC 20-152A maddeleriyle eşler. Bu bilgiler HTML, JSON ve CSV çıktılarında `regulatoryReferences` alanındaki `ac20115d`, `faa8110_49` ve `easaAmc_20_152a` dizilerine yayılır.

Aşağıdaki tabloda, her DO-178C tablosu için yerleşik referanslar listelenmiştir:

| DO-178C Tablosu | AC 20-115D | FAA 8110.49A | EASA AMC 20-152A |
| --- | --- | --- | --- |
| A-3 | §6.3, §6.5 | §2.3, §3.4 | §5.1.1, §5.1.3 |
| A-4 | §6.6, §6.7 | §5.4 | §6.2.1, §6.2.2 |
| A-5 | §7.1, §7.2 | §6.3, §6.5 | §6.3.1, §6.3.3 |
| A-6 | §7.3, §7.4 | §7.4 | §6.4.1, §6.4.2 |
| A-7 | §8.1, §8.4 | §9.3, §9.5 | §6.6.1, §6.6.2 |

Rapor çıktılarında yeni `easaAmc_20_152a` dizisi boş olmadığında, kullanıcı arayüzü AMC referanslarını AC 20-115D ve FAA 8110.49A alıntılarının yanında gösterir. Böylece aynı hedefin FAA ve EASA beklentileri tek satırda izlenebilir.

## Uyum snapshot'larında bağımsızlık özeti

`generateComplianceSnapshot` çıktısı, bağımsız kanıt eksikliklerini de raporlar. Snapshot yapısındaki `independenceSummary` alanı şu bilgileri içerir:

- `objectives`: Bağımsız kanıtı bulunmayan hedeflerin listesi. Her kayıt, hedefin kimliğini, bağımsızlık seviyesini (`recommended` veya `required`), mevcut durumunu (`covered`/`partial`/`missing`) ve bağımsız kanıtı eksik olan artefakt türlerini içerir.
- `totals`: Bağımsız kanıt eksikliğinin duruma göre dağılımını (`partial` ve `missing`) sayısal olarak gösterir. Böylece bağımsızlık riskleri raporlama katmanında tek bir bloktan takip edilebilir.

Bu özet, bağımsızlık gereksinimleri bulunan hedeflerde kanıt sağlansa bile bağımsız imza atlanmışsa kullanıcıyı bilgilendirir ve kapanmayan bağımsızlık açıklarını hızlıca tespit etmeye yardımcı olur.

## Bayat kanıt denetimi

`buildGapAnalysis` fonksiyonu, eksik artefaktlara ek olarak `staleEvidence` alanında kanıt tazeliğini de raporlar. Bu liste her hedef ve artefakt çifti için şu bilgileri içerir:

- `objectiveId` ve `artifactType`: Etkilenen hedef ve artefakt türü.
- `latestEvidenceTimestamp`: Kanıt indeksindeki en güncel kaydın zaman damgası.
- `reasons`: `beforeSnapshot` (kanıt, workspace snapshot zamanından eski) veya `exceedsMaxAge` (kanıt, yapılandırılan gün eşik değerini aşıyor) uyarıları.
- `ageDays` ve `maxAgeDays`: Kanıtın kaç günlük olduğuna dair yaklaşık değer ile kullanılan eşik.

Varsayılan olarak yaş kontrolü 90 gün ile sınırlandırılır ve çalışma alanındaki snapshot damgası (varsa) referans alınır. `generateComplianceSnapshot` çağrısı sırasında `gapRules.staleEvidence` ayarıyla bu davranış özelleştirilebilir:

```ts
generateComplianceSnapshot(bundle, {
  gapRules: {
    staleEvidence: {
      maxAgeDays: 45,
      overrides: { objectives: { 'A-6-02': 120 } },
    },
  },
});
```

Bu örnek tüm hedeflerde 45 günlük eşik uygular ancak `A-6-02` için limiti 120 güne çıkarır. Parametreye `snapshotTimestamp` veya `analysisTimestamp` verilerek farklı referans zamanları da belirlenebilir. Böylece raporlanan boşluklar sadece eksik kanıtları değil, güncelliğini yitirmiş kanıtları da kapsar.

## Sunucu uyum özet API'si

SOIPack Server, kiracıların son uyum kayıtlarını hızlıca tüketebilmesi için `GET /v1/compliance/summary` uç noktasını sunar. Yanıt yapısı şu alanları içerir:

- `computedAt`: Özetin hesaplandığı ISO zaman damgası.
- `latest`: En güncel uyum kaydının bilgileri ya da hiç kayıt yoksa `null`.
  - `summary`: Hedeflerin `covered`/`partial`/`missing` dağılımı.
  - `coverage`: Son kapsam raporundan `statements`/`branches`/`functions`/`lines` yüzdeleri.
  - `gaps.missingIds` ve `gaps.partialIds`: Kapsaması eksik hedef kimlikleri ve `openObjectiveCount` toplam açık hedef sayısı.

Sonuçlar 60 saniyelik bir önbellekten (`Cache-Control: private, max-age=60`) servis edilir; yeni bir uyum kaydı yüklendiğinde önbellek temizlenir. Böylece paneller her istek için ağır JSON dosyalarını okumadan güncel hedef durumlarını gösterebilir.

## Veri akışı

1. Dış kaynaklardan gelen kanıtlar `EvidenceIndex` yapısına taşınır.
2. `objectiveCatalog` içindeki hedefler sertifikasyon seviyesine göre değerlendirilir.
3. `buildComplianceMatrix` çıktısı, raporlama ya da kullanıcı arayüzü katmanlarında görselleştirilmek üzere kullanılabilir.

Bu yaklaşım, uyum boşluklarını otomatik olarak saptayarak sertifikasyon hazırlığında tutarlı bir denetim izi sağlar.
