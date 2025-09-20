# SOIPack

SOIPack, yazılım odaklı organizasyonların gereksinim, test, kod ve kalite artefaktlarını bağlamak için tasarlanmış uçtan uca bir izlenebilirlik platformunun monorepo iskeletidir. Monorepo; çekirdek domain türleri, farklı artefakt bağdaştırıcıları, izlenebilirlik motoru, raporlama çıktıları, CLI ve REST API katmanlarını tek bir yerde toplar.

## Paketler

- **@soipack/core** – Gereksinim ve test domain şemaları, ortak türler.
- **@soipack/adapters** – Jira CSV, ReqIF, JUnit XML, LCOV/Cobertura ve Git gibi kaynaklardan veri bağdaştırıcılarının temel iskeleti.
- **@soipack/engine** – Hedef eşleme ve izlenebilirlik hesaplamalarını yöneten çekirdek motor.
- **@soipack/report** – HTML/JSON rapor şablonları ve Playwright tabanlı PDF üretimi için yardımcılar.
- **@soipack/cli** – İzlenebilirlik işlemlerini otomatikleştiren komut satırı istemcisi.
- **@soipack/server** – Express ve OpenAPI tabanlı REST servisleri.

## Başlarken

```bash
npm install
```

### Geliştirme Komutları

| Komut                  | Açıklama                                   |
| ---------------------- | ------------------------------------------ |
| `npm run build`        | Tüm paketleri TypeScript ile derler.       |
| `npm run typecheck`    | Projeler için tip kontrolü gerçekleştirir. |
| `npm run lint`         | ESLint ile kod kalitesini denetler.        |
| `npm run test`         | Jest ile birim testlerini çalıştırır.      |
| `npm run format`       | Prettier ile biçimlendirme uygular.        |
| `npm run format:check` | Prettier biçimlendirmesini kontrol eder.   |

## Lisans

Bu proje [MIT Lisansı](./LICENSE) ile lisanslanmıştır.
