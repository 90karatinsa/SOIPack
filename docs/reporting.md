# Raporlama

SOIPack raporlama paketi; uyum matrisi, izlenebilirlik ve kapsam çıktıları için yeniden kullanılabilir şablonlar sunar. Bu doküman, yeni uyum+kapsam raporu dahil olmak üzere desteklenen biçimleri ve alanları açıklar.

## Uyum ve kapsam raporu

`renderComplianceCoverageReport`, hedef uyum durumunu yapısal kapsama özetiyle birleştiren bir HTML/PDF raporu üretir. Rapor aşağıdaki bölümlerden oluşur:

- **Uyum Matrisi** – DO-178C/DO-330 hedeflerine karşı sağlanan, eksik ve referans kanıtlarının listesi.
- **Gereksinim Kapsamı** – Gereksinim bazında test ve kod izleriyle ilişkili kapsam yüzdeleri.
- **Kalite Bulguları** – Güvenlik ve kalite araçlarından gelen açık bulgu listeleri.
- **Kapsam Özeti** – Statement, dallanma ve MC/DC toplamları ile dosya bazlı kapsam tablosu.
- **Kapsam Uyarıları** – MC/DC veya karar metrikleri eksik olduğunda gösterilen okunaklı uyarı listesi.
- **Risk Profili** – Kapsam boşlukları, test hataları, statik analiz bulguları ve audit bayraklarının ağırlıklı risk skoru.
- **Signoff Zaman Çizelgesi** – Workspace belgeleri için kimlerin signoff talep edip onayladığını gösteren kronolojik akış.
- **Değişiklik Talepleri Birikimi** – Jira üzerinden takip edilen DO-178C değişiklik isteklerinin durumu, atanan kişi ve ekleriyle birlikte listelenir.
- **Ledger Attestasyon Özeti** – Kanıt defteri attestation farkları sayesinde hangi kanıtların eklendiği ya da çıkarıldığı hızlıca gözlemlenir.

Rapor başlığında versiyon, manifest kimliği ve otomatik olarak `YYYY-MM-DD HH:MM UTC` formatında yazılmış rapor tarihi yer alır. Özet bölümünde hem uyum hem de kapsam metrikleri (ör. “Satır Kapsamı 68.8%”) tek satırda gösterilir.

## İzlenebilirlik matrisi CSV çıktısı

`renderTraceMatrix` fonksiyonu artık HTML düzeninin yanı sıra gereksinim→tasarım→kod→test zincirlerini düzleştiren bir CSV yardımcıyı (`trace.csv`) döner. CSV başlıkları gereksinim kimliği, kapsam durumları, eşlenen tasarım kimlikleri, kod yolları ve test durumlarını içerir. Kod yolları ve testler çoklayıcı olduğunda satırlar çapraz çarpanla çoğaltılarak her bağlantı açıkça temsil edilir. CLI çıktısı varsayılan olarak bu dosyayı `reports/trace.csv` olarak yazar; denetçiler veya otomasyonlar bu dosyayı Excel/BI araçlarına aktararak izlenebilirlik denetimlerini hızlandırabilir.

## Risk hikayesi ve signoff anlatımı

Risk bölümü, `@soipack/engine` tarafından sağlanan risk bloğunu görselleştirir. Breakdown kartları her faktörün ağırlığını ve toplam skora katkısını gösterirken, kapsam eğilim grafiği geçmiş snapshot verilerinden eğimi tahmin ederek ekiplerin trendleri tartışmasına yardımcı olur. Eksik sinyal listesi, risk hesabında varsayılan kabul edilen metrikleri vurgular.

Signoff zaman çizelgesi ise workspace servisinden gelen `pending` ve `approved` signoff kayıtlarını ISO zaman damgalarıyla kronolojik olarak sunar. Her olayda aktör bilgisi ve varsa anahtar/parmak izi özeti görüntülenir. Bu sayede raporu okuyan denetçiler, kanıt zincirinin kimler tarafından imzalandığını ve sürecin nerede beklediğini kolayca takip eder.

Değişiklik talepleri bölümü, Jira Cloud adaptörünün `fetchJiraChangeRequests` çıktısını aynen yansıtır. Her satırda talebin anahtarı, özet bilgisi, güncel durum/öncelik ve mevcut geçiş aksiyonları gösterilir. Ekler satırı, ilgili talebe yüklenen etki analizleri veya test raporlarını bağlantılı biçimde sunar. Ledger attestation tablosu ise uyum defterindeki en son snapshot köklerini ve hangi kanıt kimliklerinin eklendiğini/çıkarıldığını rozetlerle özetler; böylece denetçi defter farkını tek bakışta inceleyebilir.

## HTML doğrulaması

Rapor şablonları W3C doğrulamasından geçecek şekilde tasarlanmıştır. `renderComplianceCoverageReport` ile üretilen HTML, `html-validator` paketi aracılığıyla jest testlerinde kontrol edilir; sonuçtaki `messages` dizisinde hata tipi bulunan kayıt olmamalıdır.

## PDF oluşturma

`printToPDF` yardımıyla Playwright kullanılarak PDF çıktısı oluşturulur. Testler, sayfa içeriğinin başlık ve tarih bilgilerini içerdiğini ve kapsam uyarılarının madde işaretli listede yer aldığını doğrular. `printToPDF` çağrısına sağlanan `version`, `manifestId` ve `generatedAt` değerleri başlık ve altbilgide gösterilir. Böylece hem HTML hem de PDF sürümleri aynı veri kaynağından üretilebilir.
