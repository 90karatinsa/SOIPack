# Katkı Rehberi

SOIPack monoreposuna katkıda bulunmak istediğiniz için teşekkürler! Bu depo; izlenebilirlik odaklı araçları tek bir yerde toplamak için oluşturulmuş bir TypeScript monoreposudur.

## Başlangıç

1. Depoyu forklayın ve yerel ortamınıza klonlayın.
2. `npm install` komutu ile bağımlılıkları kurun.
3. Değişikliklerinizi ilgili paket altında gerçekleştirin. Yeni paketler için `packages/` dizin yapısını kullanın.

## Kod Stili

- Tüm TypeScript dosyaları için `npm run lint` ve `npm run format` komutlarını çalıştırın.
- Tip güvenliği kritik olduğundan `npm run typecheck` ve `npm run test` komutları geçilmelidir.
- Her paket için jest testleri `src` dizininde tutulur.

## Git İş Akışı

- Özellikler ve hatalar için ayrı branch kullanın.
- Açtığınız Pull Request'lerde yaptığınız değişiklikleri ve test sonuçlarını açıklayın.
- PR'ler birleşmeden önce CI kontrollerinin tamamı geçmelidir.

## Soru ve Geri Bildirim

Sorularınızı veya önerilerinizi Github Issues üzerinden paylaşabilirsiniz.
