# SOIPack Müşteri Kabul Kontrol Listesi

Bu kontrol listesi, SOIPack demo paketinin müşteri veya denetçi tesliminden önce doğrulanması gereken adımları tanımlar. Her madde tamamlandığında tarih ve sorumlu kişi kaydedilmelidir.

## Hazırlık
- [ ] Depo kökünde `npm install` komutu çalıştırıldı ve bağımlılıklar başarıyla yüklendi.【F:README.md†L24-L33】
- [ ] `scripts/make-demo.sh` betiği hava boşluklu veya izole ortamda çalıştırıldı; terminal çıktısı arşivlendi.【F:docs/demo_script.md†L10-L17】
- [ ] Lisans dosyası (`LICENSE`) ve müşteri lisans anahtarları doğrulandı; CLI tarafından hata üretilmedi.【F:docs/demo_script.md†L10-L17】【F:packages/cli/src/index.ts†L40-L115】

## Rapor Doğrulaması
- [ ] `dist/reports/compliance_matrix.html` açılarak tüm DO-178C hedefleri gözden geçirildi; eksik kanıt işaretleri not edildi.【F:docs/demo_script.md†L18-L22】
- [ ] `dist/reports/gaps.html` kontrol edilerek kırmızı satırlar için açıklama/ticket referansları eklendi.【F:docs/demo_script.md†L22-L23】
- [ ] `dist/reports/trace_matrix.html` üzerinden rastgele gereksinim → test → kod zinciri örnekleri takip edildi.【F:docs/demo_script.md†L23-L24】
- [ ] `dist/reports/compliance_matrix.pdf` müşteri arşivi için saklandı ve hash değeri kabul raporuna eklendi.【F:docs/demo_script.md†L18-L25】

## Paket ve Güvenlik
- [ ] `release/manifest.json` ve `manifest.sig` dosyaları saklandı; hash doğrulaması bağımsız olarak tekrarlandı.【F:docs/demo_script.md†L26-L31】
- [ ] `release/soi-pack-*.zip` arşivi açılarak raporların ve manifestlerin paket içinde bulunduğu teyit edildi.【F:docs/demo_script.md†L26-L31】
- [ ] `/v1/packages/<paket-id>/archive` ve `/v1/packages/<paket-id>/manifest` uç noktaları yetkili token ile test edildi; farklı tenant token'ı erişim sağlayamadı.【F:packages/server/src/index.ts†L1462-L1493】【F:packages/server/src/index.test.ts†L706-L744】
- [ ] `node packages/cli/dist/index.js download --api <URL> --token <TOKEN> --package <paket-id>` komutu ile arşiv ve manifest indirildi; çıktılar teslimat paketine eklendi.【F:packages/cli/src/index.ts†L1437-L1564】
- [ ] Anahtar yönetimi prosedürleri `docs/soipack_security.md` ile uyumlu şekilde belgelenmiş ve müşteriye iletilmiştir.【F:docs/soipack_security.md†L1-L64】

## Teslimat
- [ ] Raporlar ve paket, müşteri tarafından belirtilen kanallar üzerinden paylaşıldı (örn. güvenli dosya transferi, fiziksel medya).
- [ ] `docs/soipack_user_guide.md` ve `docs/soipack_tool_assessment_stub_DO330.md` dokümanları teslimat paketine eklendi.
- [ ] Kabul toplantısı sırasında raporların canlı gösterimi planlandı ve `docs/demo_script.md` akışına göre prova yapıldı.【F:docs/demo_script.md†L1-L31】

Bu liste tamamlandığında müşteri kabul onayı alınabilir ve SOIPack artefaktları resmi denetim arşivine aktarılabilir.
