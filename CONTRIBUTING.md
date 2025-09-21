# Katkı Rehberi

SOIPack monoreposuna katkıda bulunmak istediğiniz için teşekkürler! Bu depo; izlenebilirlik odaklı araçları tek bir yerde toplamak için oluşturulmuş bir TypeScript monoreposudur.

## Başlangıç

1. Depoyu forklayın ve yerel ortamınıza klonlayın.
2. `npm install` komutu ile bağımlılıkları kurun.
3. Değişikliklerinizi ilgili paket altında gerçekleştirin. Yeni paketler için `packages/` dizin yapısını kullanın.

## Kod Stili

- Tüm TypeScript dosyaları için `npm run lint` ve `npm run format` komutlarını çalıştırın.
- Tip güvenliği kritik olduğundan `npm run typecheck`, `npm run test` ve `npm run openapi:validate` komutları geçilmelidir.
- Her paket için jest testleri `src` dizininde tutulur.

## Git İş Akışı

- Özellikler ve hatalar için ayrı branch kullanın.
- Açtığınız Pull Request'lerde yaptığınız değişiklikleri ve test sonuçlarını açıklayın.
- PR'ler birleşmeden önce CI kontrollerinin (`npm run lint`, `npm run typecheck`, `npm run test`, `npm run openapi:validate`) tamamı geçmelidir.

## Soru ve Geri Bildirim

Sorularınızı veya önerilerinizi Github Issues üzerinden paylaşabilirsiniz.
