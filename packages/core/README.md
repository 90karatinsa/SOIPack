# @soipack/core

SOIPack çekirdek paketi, gereksinim tanımları, kanıt şemaları ve sürümleme yardımcılarının yanı sıra yeni Merkle tabanlı kayıt defteri (ledger) araçlarını içerir. Bu belge, ledger tasarımını ve tipik kullanım örneklerini açıklar.

## Merkle ledger tasarımı

`createLedger`, denetlenebilir kanıt zinciri oluşturmak için kullanılabilecek boş bir kayıt defteri döndürür. Ledger, her eklenen girdinin önceki durumun hash'i ile birleştirildiği doğrusal bir zincir olarak modellenmiştir. Her giriş için aşağıdaki bileşenler Merkle ağacına yaprak olarak eklenir:

- Snapshot kimliği (`snapshotId`)
- Manifest özeti (`manifestDigest` – SHA-256)
- Zaman damgası (`timestamp` – ISO 8601)
- Varsa, her kanıt bağlantısı (`snapshotId`, dosya yolu ve kanıt hash'i)

Yapraklar sıralanır ve ikili olarak birleştirilerek tek bir Merkle kökü elde edilir. Bu kök, mevcut ledger kökü ile birlikte tekrar hash'lenir ve yeni `ledgerRoot` değeri oluşturulur. Böylece her giriş, geçmişteki tüm kayıtların kriptografik olarak bağlandığı bir zincir oluşturur.

## İmza ve doğrulama

`appendEntry`, isteğe bağlı olarak Ed25519 anahtarıyla imzalama yapabilir. `LedgerSignerOptions` ile sağlanan özel anahtar, hesaplanan `ledgerRoot` değerini imzalar ve imza kayıtla birlikte saklanır. Doğrulama sırasında `verifyLedger` fonksiyonu:

1. Her girdinin Merkle kökünü yeniden hesaplar.
2. Önceki kök ile mevcut kökün uyumunu kontrol eder.
3. Varsa imzayı Ed25519 ile doğrular.
4. Ledger'ın son kökünün beklenen değerle eşleştiğini garanti eder.

Bir önceki kökte manipülasyon yapılırsa `LedgerBranchError`, imza geçersizse `LedgerSignatureError` fırlatılır.

## Örnek kullanım

```ts
import { appendEntry, createLedger, verifyLedger } from '@soipack/core';

let ledger = createLedger();
ledger = appendEntry(ledger, {
  snapshotId: 'SNAP-001',
  manifestDigest: 'aabbcc...ff',
  timestamp: '2024-02-01T12:00:00Z',
  evidence: [{ snapshotId: 'SNAP-001', path: 'reports/summary.html', hash: 'deafbeef...' }],
});

ledger = appendEntry(ledger, {
  snapshotId: 'SNAP-002',
  manifestDigest: '112233...99',
  timestamp: '2024-02-03T09:30:00Z',
});

const verification = verifyLedger(ledger);
console.log(verification.root); // Ledger kökü tüm kayıtları temsil eder.
```

Bu yapı sayesinde, paketleyici veya raporlama araçları manifest zincirini doğrulayabilir, kanıt belgeleri ile snapshot sürümlerini birbirine bağlayabilir ve herhangi bir dal sapması veya imza bozulmasını anında tespit edebilir.
