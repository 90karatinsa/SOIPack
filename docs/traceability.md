# İzlenebilirlik Boşluk Analizi

SOIPack Engine, gereksinim → tasarım → kod → test zincirinin sürekliliğini doğrulamak için `TraceabilityGapAnalyzer` modülünü sağlar. Bu analiz, her gereksinimin doğrulanabilir bir kanıt zincirine sahip olduğundan emin olmak ve boşlukları önceliklendirmek amacıyla kullanılır.

## Kurallar

Analiz şu kontrolleri uygular:

- **Eksik halkalar:** Gereksinimlerin tasarım, kod veya test bağlantısı yoksa boşluk olarak raporlanır.
- **Çelişkili eşleşmeler:** Bağlantılar tek yönlü veya tutarsız olduğunda (örneğin kod bir testi referans eder ancak test aynı kodu doğrulamaz) çatışma kaydı oluşturulur.
- **Yetim varlıklar:** Hiçbir gereksinimle ilişkilendirilmeyen tasarım ve kod bileşenleri ile herhangi bir kodu doğrulamayan testler işaretlenir.
- **Geçersiz referanslar:** Modelde bulunmayan kimliklere yapılan atıflar yüksek öncelikli çakışma olarak belirtilir.

## Önceliklendirme

Gereksinim boşlukları aşağıdaki şiddet seviyeleriyle sınıflandırılır:

| Şiddet | Kriter |
| ------ | ------ |
| `high` | Test kanıtı bulunmayan gereksinimler veya test zincirinde çelişki. |
| `medium` | Tasarım var ancak kod bağlantısı eksik. |
| `low` | Sadece tasarım bağlantısı eksik (diğer halkalar mevcut). |

`summary.highPriorityRequirements` alanı, kapatılması gereken gereksinimleri hızlıca öne çıkarır.

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
