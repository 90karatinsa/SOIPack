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
