# SOIPack v0.1.0 Sürüm Notları

## Öne Çıkanlar
- Tüm CLI komutları artık Ed25519 imzalı lisans anahtarlarını çevrimdışı doğrulayan `verifyLicenseFile` akışını paylaşıyor; eksik veya süresi dolmuş lisanslar hata üreterek pipeline'ı durduruyor.【F:packages/cli/src/license.ts†L19-L142】
- İzlenebilirlik raporu testleri, fixture zaman damgasını `renderTraceMatrix` çağrısına geçirerek deterministik HTML üretimini doğruluyor; güncellenen golden dosyası rapor tarihinin sabitlendiğini gösteriyor.【F:packages/report/src/index.test.ts†L42-L52】【F:packages/report/src/__fixtures__/goldens/trace-matrix.html†L234-L255】
- `examples/minimal/demo.sh` artık depo ile gelen demo lisansını otomatik iletip referans artefaktları senkronize ediyor; EXPECTED klasörü manifest ve imza ile güncel tutulurken zip paketi yalnızca demo çıktısı olarak üretiliyor.【F:examples/minimal/demo.sh†L4-L128】【F:examples/minimal/EXPECTED/manifest.json†L1-L34】【F:examples/minimal/EXPECTED/manifest.sig†L1-L1】

## Kullanım ve Dokümantasyon
- README ve kullanıcı rehberi, 5 dakikalık demo adımlarında `--license data/licenses/demo-license.key` bayrağının gerekli olduğunu açıkça belirtiyor.【F:README.md†L32-L89】【F:docs/soipack_user_guide.md†L33-L72】
- Dağıtım rehberi, air-gapped hazırlık adımlarına kurum içi registry'e `docker push` örneğini ekledi; etiket ve URL'yi nasıl özelleştireceğiniz belgeleniyor.【F:docs/deploy.md†L25-L35】

## Paket Artefaktları
- Demo paketine ait manifest ve imza dosyaları yenilendi; doğrulama betikleri release klasöründeki zip paketini kontrol ederken `EXPECTED` klasörü sadece manifest ve imza ile eşleniyor.【F:examples/minimal/EXPECTED/manifest.json†L1-L34】【F:examples/minimal/EXPECTED/manifest.sig†L1-L1】【F:examples/minimal/verify-demo.js†L44-L63】
