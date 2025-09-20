# Satış Öncesi 5 Dakikalık Demo Akışı

Bu metin, müşteri görüşmesi başlamadan hemen önce tek komutla çalışan SOIPack demosunu sunmak için hazırlanmıştır.

## 0:00 - 1:00 · Başlangıç ve Hazırlık
- "SOIPack"in gereksinim-test izlenebilirliğini uçtan uca yönettiğini vurgulayın.
- Depo kökünde olduğunuzu gösterin ve lisansın proje ile birlikte geldiğini belirtin.
- Terminalde tek komutluk betiği tanıtın:
  ```bash
  ./scripts/make-demo.sh
  ```
- Komutun örnek veriyi izole ettiğini, lisansı doğruladığını ve derlemeyi otomatik yürüttüğünü anlatın.

## 1:00 - 2:30 · Betiği Çalıştırma
- Komutu başlatın ve çıktı boyunca önemli log satırlarını yüksek sesle okuyun.
  - "Demo çalışma alanı hazırlanıyor" mesajı ile temiz ortamdan bahsedin.
  - "soipack run" satırında YAML konfigürasyonunun uçtan uca boru hattını tetiklediğini açıklayın.
- Log sonunda görünen rapor ve paket yollarını birlikte inceleyerek HTML/PDF raporlarının ve `release/soi-pack-*.zip` paketinin hazır olduğunu doğrulayın.

## 2:30 - 4:00 · Raporları Sunma
- Terminalin yazdırdığı `compliance_matrix.html` dosyasını tarayıcıda açın ve hedef-kanıt eşleşmelerini gösterin.
- `gaps.html` dosyasında eksik kanıtların kırmızı olarak işaretlendiğini vurgulayın.
- `trace_matrix.html` üzerinden gereksinim → test → kod zincirini takip ederek kapsamlı izlenebilirlikten bahsedin.
- Python ile üretilen `compliance_matrix.pdf` özetinin müşteriye e-posta veya denetim arşivi için hazır olduğuna değinin.

## 4:00 - 5:00 · Paket ve Kapanış
- `release/soi-pack-*.zip` arşivini göstererek tüm artefaktların tek dosyada toplandığını anlatın.
- Manifest imzasının (manifest.json + manifest.sig) zip ile birlikte geldiğini, böylece doğrulanabilir paketler üretildiğini söyleyin.
- Son olarak müşteriye komutu paylaşabileceğinizi, kendi verileriyle de aynı akışı tekrar edebileceklerini hatırlatın.
