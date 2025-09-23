# Güvenlik Politikası

SOIPack, güvenliğe önem verir. Güvenlik açıklarını sorumlu bir şekilde bildirmek için aşağıdaki adımları takip edin.

## Açık Bildirme

- Açığı `security@soipack.example` adresine e-posta ile bildirin.
- Raporunuzda açık açıklaması, yeniden üretim adımları ve olası etkiyi paylaşın.
- Açık, halka duyurulmadan önce çözüm üzerinde birlikte çalışacağız.

## Desteklenen Sürümler

Bu monorepo iskeleti aktif geliştirme aşamasındadır ve tüm sürümler güvenlik yamaları almaktadır.

## Yeni Güvenlik Özellikleri

- Üretim dağıtımlarında varsayılan olarak etkinleştirilen çalışma zamanı bütünlük kontrolleri, kritik konfigürasyon değişikliklerini izler ve beklenmeyen sapmaları engeller.
- Sunucu tarafında otomatik tehdit modelleme iş akışları, yeni bileşenler CI/CD'ye eklendiğinde güvenlik değerlendirmesini zorunlu kılar.
- Denetim günlükleri, uzun süreli saklama için şifrelenmiş depolama alanına aktarılır ve olay müdahalesi ekibine gerçek zamanlı uyarılar üretir.

## API Anahtarı Yönetimi

- API anahtarları proje, ortam ve izin kapsamlarına göre isimlendirilmek ve RBAC ilkeleri ile sınırlandırılmak zorundadır.
- Anahtar rotasyonu maksimum 90 günde bir yapılmalı, rotasyon tarihleri CI metadata'larında kayıt altına alınmalı ve eski anahtarlar otomatik olarak iptal edilmelidir.
- Şüpheli etkinlikler tespit edildiğinde anahtarlar derhal askıya alınmalı ve etkilenen kullanıcılar güvenli iletişim kanallarından bilgilendirilmelidir.

## İmza Gereksinimleri

- Tüm yayınlanan paketler, konteyner görüntüleri ve CLI ikili dosyaları Sigstore tabanlı şeffaflık günlüğünde doğrulanabilir bir imza ile imzalanmalıdır.
- İmzalar, `ops-signing@soipack.example` tarafından yönetilen donanım destekli anahtar kasasında saklanır ve erişim talepleri en az iki kişilik onay mekanizmasına tabidir.
- CI/CD hatları, imzasız veya geçersiz imza tespit edilmesi halinde derlemeyi otomatik olarak durdurur ve güvenlik ekibine bildirim gönderir.
