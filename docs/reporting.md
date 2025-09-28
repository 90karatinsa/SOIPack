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
- **Bağımsızlık Uyarıları** – Zorunlu veya önerilen bağımsız doğrulama gerektiren hedeflerdeki eksik kanıtları rozetlerle öne çıkarır.
- **Signoff Zaman Çizelgesi** – Workspace belgeleri için kimlerin signoff talep edip onayladığını gösteren kronolojik akış.
- **Değişiklik Talepleri Birikimi** – Jira üzerinden takip edilen DO-178C değişiklik isteklerinin durumu, atanan kişi ve ekleriyle birlikte listelenir.
- **Ledger Attestasyon Özeti** – Kanıt defteri attestation farkları sayesinde hangi kanıtların eklendiği ya da çıkarıldığı hızlıca gözlemlenir.

Rapor başlığında versiyon, manifest kimliği ve otomatik olarak `YYYY-MM-DD HH:MM UTC` formatında yazılmış rapor tarihi yer alır. Özet bölümünde hem uyum hem de kapsam metrikleri (ör. “Satır Kapsamı 68.8%”) tek satırda gösterilir.

### SOI aşaması sekmeleri

Uyum matrisi bölümü artık DO-178C Stage of Involvement (SOI) aşamalarını ayrı sekmeler olarak sunar. `@soipack/engine` tarafında `buildComplianceMatrix({ stage })` parametresi ile oluşturulan bu görünüm, JSON çıktısında `stages` dizisi olarak döner ve her kayıt seçili aşamadaki hedef kimliklerini ve özet sayılarını içerir. HTML/PDF şablonu bu diziyi kullanarak "Tüm Stajlar" sekmesi ile birlikte SOI-1…SOI-4 başlıklarını üretir; her sekmede yalnızca ilgili hedeflerin kanıt durumu listelenir.

Operasyon ekipleri raporu açtığında üst bölümdeki sekmeler üzerinden planlama (SOI-1), geliştirme (SOI-2) ve doğrulama (SOI-3) hedeflerine hızla geçiş yapabilir. UI uygulaması da aynı `stages` dizisini kullanır; ComplianceMatrix bileşeni seçilen aşamayı yerel depolamada saklayarak kullanıcılar sekmeler arasında geçse dahi tercih edilen SOI görünümünü korur. Böylece SOIPack raporları hem denetim masasında hem de demo arayüzünde aşama bazlı izlenebilirliği tutarlı şekilde gösterir.

### Bağımsızlık göstergeleri

Uyum matrisi artık DO-178C bağımsız doğrulama gereksinimlerini özetleyen ayrı bir bölüm içerir. Rapordaki “Bağımsızlık Uyarıları” bloğunda toplam etkilenen hedef sayısı, kısmi/eksik durumlar ve hedeflerin zorunlu/önerilen bağımsızlık seviyeleri rozetlerle vurgulanır. Kırmızı (`Zorunlu`) rozetler sertifikasyon için kritik eksiklikleri, sarı (`Önerilen`) rozetler ise bağımsız inceleme bekleyen alanları gösterir. Tablo satırlarında eksik kanıt türleri (ör. `Gözden Geçirme`, `MC/DC Kapsamı`) ayrı rozetler halinde listelenir ve denetçilerin hangi kanıtların bağımsız gözden geçirme gerektirdiğini hızlıca görmesini sağlar. Eğer bağımsızlık eksikliği kalmamışsa bölüm “Bağımsızlık gerektiren hedeflerde eksik bulunamadı.” mesajıyla kapanır.

## İzlenebilirlik matrisi CSV çıktısı

`renderTraceMatrix` fonksiyonu artık HTML düzeninin yanı sıra gereksinim→tasarım→kod→test zincirlerini düzleştiren bir CSV yardımcıyı (`trace.csv`) döner. CSV başlıkları gereksinim kimliği, kapsam durumları, eşlenen tasarım kimlikleri, kod yolları ve test durumlarını içerir. Kod yolları ve testler çoklayıcı olduğunda satırlar çapraz çarpanla çoğaltılarak her bağlantı açıkça temsil edilir. CLI çıktısı varsayılan olarak bu dosyayı `reports/trace.csv` olarak yazar; denetçiler veya otomasyonlar bu dosyayı Excel/BI araçlarına aktararak izlenebilirlik denetimlerini hızlandırabilir.

## Uyum matrisi CSV çıktısı

`renderComplianceMatrix` çağrıları, HTML ve JSON çıktılarının yanında tüm uyum hedeflerini içeren bir CSV özet (`compliance.csv`) döndürür. Her satır hedef kimliğini, referans tablosunu, SOI aşamasını, yerelleştirilmiş durum etiketini, sağlanan/eksik kanıt rozetlerini ve varsa kanıt referanslarını listeler. Kanıt dizileri CSV içinde `|` karakteriyle birleştirildiğinden, Excel veya BI araçlarında filtrelemek kolaydır.

SOI sekmeleri için kullanılan veri yapısı CSV yardımcısında da bulunduğundan, dönen `csv.stages` alanı her bir SOI aşaması için alt CSV dizilerini üretir (`SOI-1`, `SOI-2`, `SOI-3`, `SOI-4`). CLI `run report` komutu HTML ve JSON ile birlikte bu dosyayı `reports/compliance.csv` olarak kaydeder; böylece denetçiler belirli bir aşamadaki eksik kanıtları komut satırından çalıştırılan pipeline sonrasında doğrudan inceleyebilir.

## Risk hikayesi ve signoff anlatımı

Risk bölümü, `@soipack/engine` tarafından sağlanan risk bloğunu görselleştirir. Breakdown kartları her faktörün ağırlığını ve toplam skora katkısını gösterirken, kapsam eğilim grafiği geçmiş snapshot verilerinden eğimi tahmin ederek ekiplerin trendleri tartışmasına yardımcı olur. Eksik sinyal listesi, risk hesabında varsayılan kabul edilen metrikleri vurgular.

Signoff zaman çizelgesi ise workspace servisinden gelen `pending` ve `approved` signoff kayıtlarını ISO zaman damgalarıyla kronolojik olarak sunar. Her olayda aktör bilgisi ve varsa anahtar/parmak izi özeti görüntülenir. Bu sayede raporu okuyan denetçiler, kanıt zincirinin kimler tarafından imzalandığını ve sürecin nerede beklediğini kolayca takip eder.

Değişiklik talepleri bölümü, Jira Cloud adaptörünün `fetchJiraChangeRequests` çıktısını aynen yansıtır. Her satırda talebin anahtarı, özet bilgisi, güncel durum/öncelik ve mevcut geçiş aksiyonları gösterilir. Ekler satırı, ilgili talebe yüklenen etki analizleri veya test raporlarını bağlantılı biçimde sunar. Ledger attestation tablosu ise uyum defterindeki en son snapshot köklerini ve hangi kanıt kimliklerinin eklendiğini/çıkarıldığını rozetlerle özetler; böylece denetçi defter farkını tek bakışta inceleyebilir.

## HTML doğrulaması

Rapor şablonları W3C doğrulamasından geçecek şekilde tasarlanmıştır. `renderComplianceCoverageReport` ile üretilen HTML, `html-validator` paketi aracılığıyla jest testlerinde kontrol edilir; sonuçtaki `messages` dizisinde hata tipi bulunan kayıt olmamalıdır.

## PDF oluşturma

`printToPDF` yardımıyla Playwright kullanılarak PDF çıktısı oluşturulur. Testler, sayfa içeriğinin başlık ve tarih bilgilerini içerdiğini ve kapsam uyarılarının madde işaretli listede yer aldığını doğrular. `printToPDF` çağrısına sağlanan `version`, `manifestId` ve `generatedAt` değerleri başlık ve altbilgide gösterilir. Böylece hem HTML hem de PDF sürümleri aynı veri kaynağından üretilebilir.
