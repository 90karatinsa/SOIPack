# İzlenebilirlik Boşluk Analizi

SOIPack Engine, gereksinim → tasarım → kod → test zincirinin sürekliliğini doğrulamak için `TraceabilityGapAnalyzer` modülünü sağlar. Bu analiz, her gereksinimin doğrulanabilir bir kanıt zincirine sahip olduğundan emin olmak ve boşlukları önceliklendirmek amacıyla kullanılır.

## Kurallar

Analiz şu kontrolleri uygular:

- **Eksik halkalar:** Gereksinimlerin tasarım, kod veya test bağlantısı yoksa boşluk olarak raporlanır.
- **Çelişkili eşleşmeler:** Bağlantılar tek yönlü veya tutarsız olduğunda (örneğin kod bir testi referans eder ancak test aynı kodu doğrulamaz) çatışma kaydı oluşturulur.
- **Yetim varlıklar:** Hiçbir gereksinimle ilişkilendirilmeyen tasarım ve kod bileşenleri ile herhangi bir kodu doğrulamayan testler işaretlenir.
- **Geçersiz referanslar:** Modelde bulunmayan kimliklere yapılan atıflar yüksek öncelikli çakışma olarak belirtilir.
- **Belirsiz dil sezgileri:** Hem İngilizce hem Türkçe metinlerde "TBD", "as appropriate", "olmalı", "gerektiğinde" veya "yeterli" gibi yer tutucu/yorum açık ifadeler algılandığında kalite uyarıları üretilir.

## Önceliklendirme

Gereksinim boşlukları aşağıdaki şiddet seviyeleriyle sınıflandırılır:

| Şiddet | Kriter |
| ------ | ------ |
| `high` | Test kanıtı bulunmayan gereksinimler veya test zincirinde çelişki. |
| `medium` | Tasarım var ancak kod bağlantısı eksik. |
| `low` | Sadece tasarım bağlantısı eksik (diğer halkalar mevcut). |

`summary.highPriorityRequirements` alanı, kapatılması gereken gereksinimleri hızlıca öne çıkarır.

## Değişiklik Etki Analizi ve Git değişkenliği

`analyzeChangeImpact` fonksiyonu, iki iz grafiği arasındaki farkları inceleyerek gereksinim, tasarım, kod ve test düğümlerinin riskini hesaplar. Motor, temel değişikliklerin yanı sıra Git geçmişinden türetilen değişkenlik sinyallerini de değerlendirir:

- **Recent commits:** Son çalışma haftalarındaki commit sayısı `gitRecentCommitWeight` (varsayılan `0.8`) ile çarpılır.
- **Diff size:** Toplam satır ekleme/çıkarma miktarı `log1p` ile sıkıştırılır ve `gitDiffSizeWeight` (varsayılan `0.04`) ile ölçeklenir.
- **Branch divergence:** Özellik dalının ana dal ile ayrıştığı commit sayısı `gitBranchDivergenceWeight` (varsayılan `1.2`) ile ağırlıklandırılır.

Toplam volatilite, ilgili kod düğümünün temel skoruna eklenir ve bağlantılı gereksinim/tasarım düğümlerine dalga etkisiyle yayılır. Böylece yakın zamanda yoğun değişikliğe uğramış dosyalar, doğrudan içerik farkı olmasa bile yüksek riskli olarak raporlanır.

İsteğe bağlı `gitMetrics` seçeneği ile bu veriler çalışma alanına enjekte edilebilir:

```ts
import { analyzeChangeImpact } from '@soipack/engine';

const gitMetrics = {
  'code:src/controllers/auth.ts': { recentCommits: 6, diffSize: 180, branchDivergence: 2 },
  'src/shared/validators.ts': { recentCommits: 1, diffSize: 12, branchDivergence: 0 },
};

const scores = analyzeChangeImpact(baselineGraph, currentGraph, { gitMetrics });
```

Anahtar hem `code:` ile başlayan düğüm anahtarı hem de çıplak dosya yolu ile eşleşebilir. Kuruluşlar ağırlıkları `weights` parametresiyle özelleştirerek kendi risk eşiklerini uygulayabilir.

## Toleranslar

- Sağlık kontrolleri veya yardımcı testler gibi kodla eşleşmeyen testler, manuel olarak hariç tutulmadıkça çatışma olarak raporlanır.
- Zincirin her halkasının varlığı çift yönlü bağlantıyla doğrulanır; yalnızca tek yönlü bağlantılar güvenilir kabul edilmez.
- Modeldeki kimlikler büyük/küçük harf duyarlıdır; tüm referansların normalize edilmiş olması gerekir.

## Kullanım

```ts
import traceModel from '../test/fixtures/traceability.json';
import { TraceabilityGapAnalyzer } from '@soipack/engine';

const analyzer = new TraceabilityGapAnalyzer(traceModel);
const report = analyzer.analyze();

console.log(report.summary.highPriorityRequirements);
```

`report` nesnesi gereksinim boşluklarını, yetim varlıkları ve çatışma kayıtlarını içerir. Çıktı, doğrulama planlarına beslenerek eksik kanıtların kapatılmasını sağlar.

## Tasarım Kayıtlarının İçe Aktarımı

SOIPack 2024.7 sürümüyle birlikte gereksinim ↔ tasarım ↔ kod zincirindeki ara halkaları da doğrulamak mümkündür. Tasarım kayıtları CSV üzerinden `--design-csv` bayrağı ile CLI'ya sağlanır ve çekirdek `DesignRecord` şeması kullanılarak normalize edilir.

### CSV Şeması

CSV dosyasında aşağıdaki sütunlar beklenir:

| Sütun adı | Açıklama |
| --- | --- |
| `Design ID` | Tasarımın benzersiz kimliği (zorunlu). |
| `Title` | Kısa başlık (zorunlu). |
| `Description` | Opsiyonel açıklama metni. |
| `Status` | `draft`, `allocated`, `implemented` veya `verified` durumlarından biri. |
| `Tags` | Virgül veya noktalı virgül ile ayrılmış etiket listesi; içe aktarım sırasında normalize edilir. |
| `Requirement IDs` | Tasarımın izlediği gereksinim kimlikleri; birden fazla değer `;` ile ayrılabilir. |
| `Code Paths` | İlgili kod yolları veya modül etiketleri; `;` ile ayrılabilir. |

Eksik kimlikler veya tekrarlanan referanslar bulunduğunda CLI çıktılarına uyarı olarak yansıtılır. Aynı tasarım kimliğinin birden fazla satırda yer alması hata olarak reddedilir.

### CLI Kullanımı

Aynı çalıştırmada gereksinim, test ve tasarım verilerini içe aktarmak için `analyze` ve `report` komutlarına `--design-csv` parametresini ekleyebilirsiniz:

```bash
soipack analyze --workspace workspace.json --design-csv designs.csv
soipack report --workspace workspace.json --design-csv designs.csv
```

Bu bayrak, mevcut `workspace.json` içine normalize edilmiş `designs` alanını ekler ve takip eden analiz çalıştırmalarında tekrar kullanılabilir.

### İz Matrisleri ve Boşluk Çıktıları

İçe aktarılan tasarımlar, analiz motorunda gereksinim ve kod düğümleri arasındaki yeni bir katman olarak gösterilir. `trace.html` çıktısındaki iz matrisi her gereksinim için ilişkili tasarım kimliklerini listeler; hiçbir tasarımla eşleşmeyen gereksinimler “Design” sütununda `missing` etiketiyle vurgulanır. Aynı şekilde boşluk özetinde `summary.missingDesigns` alanı doldurulur ve `highPriorityRequirements` listesine tasarım halkası eksik olan kayıtlar eklenir. Böylece ekipler tasarım üretimi veya güncellemesi gereken gereksinimleri hızlıca belirleyebilir.

## Öneri motoru ile bağlantı kapatma

Boşluk raporlarını desteklemek için SOIPack Engine `generateTraceSuggestions` fonksiyonunu sağlar. Bu modül, gereksinim tanımlarını, mevcut test sonuçlarını ve test→kod kapsam haritalarını tarayarak gözden geçiricilere sunulacak olası bağlantıları üretir. Öneri motoru aşağıdaki sezgileri kullanır:

- Gereksinim kimliğini veya normalize edilmiş anahtar kelimeleri doğrudan içeren test kimlikleri yüksek güvenle önerilir.
- Gereksinim ve test açıklamalarındaki ortak kelimeler orta/düşük güvenli eşleşmeler olarak listelenir.
- Testlerin kapsadığı ancak gereksinimde izlenmeyen kod yolları, ilgili test üzerinden kod bağlantısı önerisi olarak eklenir.

Her öneri `TraceSuggestion` arayüzünü takip eder ve `requirementId`, `type` (`test` veya `code`), `targetId`, `confidence` ile `reason` alanlarını içerir. CLI `analyze` komutu bu diziyi `analysis.json` içine `traceSuggestions` alanında ekler; `report` komutu ise `trace.html` içinde “Önerilen İz Bağlantıları” tablosunu üretir. İnceleme ekipleri bu listeyi kullanarak gereksinim kayıtlarını veya test/coderef eşleştirmelerini güncelleyebilir.

Programatik kullanım için modülü doğrudan içe aktarabilirsiniz:

```ts
import { generateTraceSuggestions } from '@soipack/engine';

const suggestions = generateTraceSuggestions(traceReport.traces, testResults, coverageMap);
suggestions
  .filter((item) => item.confidence !== 'low')
  .forEach((suggestion) => console.log(suggestion.reason));
```

Bu çıktı, gözden geçirme toplantılarında hızlıca tartışılacak bağlantı adaylarını veya otomatik JIRA görevleri açmak için kullanılabilir. Önerilerin kabul edilmesi, sonraki analiz çalıştırmalarında ilgili boşlukların kapanmasını sağlar.
