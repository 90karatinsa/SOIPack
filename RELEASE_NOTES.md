# SOIPack Release Notes

## 0.2.0 - 2024-05-01

### Güvenlik ve Uygulama Bütünlüğü
- Çalışma zamanı bütünlük kontrolleri tüm üretim dağıtımlarında varsayılan olarak etkinleştirildi.
- Sigstore tabanlı imzalama zinciri CI/CD'ye entegre edilerek imzasız yapıtlar otomatik olarak reddediliyor.
- Güvenlik olay günlükleri, şifreli arşiv depolama ve gerçek zamanlı uyarılarla genişletildi.

### API Anahtarı Yönetimi
- Anahtar oluşturma ve dağıtım süreçleri için kapsam (scope) ve ortam bazlı şablonlar tanımlandı.
- Zorunlu 90 günlük rotasyon politikası ve otomatik iptal akışları eklendi.
- Şüpheli etkinlik tespitinde anlık bildirim ve kullanıcı erişimlerinin askıya alınması destekleniyor.

### CI/CD ve Sürüm İmzalama
- CI sürüm etiketleri, imza kimliği, imzalama otoritesi ve anahtar rotasyon zaman damgalarını içerecek şekilde güncellendi.
- Yayın pipeline'ı, çekirdek paketlerin yanı sıra konteyner görüntüleri ve CLI ikilileri için aynı imza politikalarını uygular.

### Geliştirici Deneyimi
- API anahtarı kullanım rehberi ve örnek yapılandırma dosyaları belgelere eklendi.
- İmza doğrulama adımları `scripts/verify-healthcheck.js` içine entegre edilerek yerel doğrulamalar kolaylaştırıldı.

### Yayın Metadata'sı
- `release:channel=stable`
- `release:ci-tag=ci/0.2.0`
- `release:git-tag=v0.2.0`
- `release:commit-signing=required`
