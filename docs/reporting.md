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

Rapor başlığında versiyon, manifest kimliği ve otomatik olarak `YYYY-MM-DD HH:MM UTC` formatında yazılmış rapor tarihi yer alır. Özet bölümünde hem uyum hem de kapsam metrikleri (ör. “Satır Kapsamı 68.8%”) tek satırda gösterilir.

## Risk hikayesi ve signoff anlatımı

Risk bölümü, `@soipack/engine` tarafından sağlanan risk bloğunu görselleştirir. Breakdown kartları her faktörün ağırlığını ve toplam skora katkısını gösterirken, kapsam eğilim grafiği geçmiş snapshot verilerinden eğimi tahmin ederek ekiplerin trendleri tartışmasına yardımcı olur. Eksik sinyal listesi, risk hesabında varsayılan kabul edilen metrikleri vurgular.

Signoff zaman çizelgesi ise workspace servisinden gelen `pending` ve `approved` signoff kayıtlarını ISO zaman damgalarıyla kronolojik olarak sunar. Her olayda aktör bilgisi ve varsa anahtar/parmak izi özeti görüntülenir. Bu sayede raporu okuyan denetçiler, kanıt zincirinin kimler tarafından imzalandığını ve sürecin nerede beklediğini kolayca takip eder.

## HTML doğrulaması

Rapor şablonları W3C doğrulamasından geçecek şekilde tasarlanmıştır. `renderComplianceCoverageReport` ile üretilen HTML, `html-validator` paketi aracılığıyla jest testlerinde kontrol edilir; sonuçtaki `messages` dizisinde hata tipi bulunan kayıt olmamalıdır.

## PDF oluşturma

`printToPDF` yardımıyla Playwright kullanılarak PDF çıktısı oluşturulur. Testler, sayfa içeriğinin başlık ve tarih bilgilerini içerdiğini ve kapsam uyarılarının madde işaretli listede yer aldığını doğrular. `printToPDF` çağrısına sağlanan `version`, `manifestId` ve `generatedAt` değerleri başlık ve altbilgide gösterilir. Böylece hem HTML hem de PDF sürümleri aynı veri kaynağından üretilebilir.
