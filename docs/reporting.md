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

## GSN Graphviz/DOT dışa aktarımı

Uyumluluk snapshot'ları için DO-178C hedeflerini, referans kanıtlarını ve kalıcı boşlukları özetleyen bir Goal Structuring Notation (GSN) grafiği üretmek amacıyla `renderGsnGraphDot` fonksiyonu kullanılabilir. Fonksiyon Graphviz/DOT biçiminde bir dize döndürür; çıktı içerisinde SOI kümelerine ayrılmış hedef düğümleri, her hedefe bağlı kanıt (solution) düğümleri, eksik artefaktlar veya `staleEvidence` bulguları için kalıntı düğümleri ve bağımsızlık seviyelerini açıklayan bir lejant yer alır. Zorunlu bağımsızlık isteyen hedefler çift kenarlı olarak çizilir, eksikler kırmızı kalın kenarlarla vurgulanır ve legend'da bu kodlama özetlenir.

**Çalışma akışı**

1. `@soipack/engine` ile uyum snapshot'ını ve `Objective` meta verilerini oluşturun (örnek: `createReportFixture()` jest fikstürü).
2. `renderGsnGraphDot(snapshot, { objectivesMetadata, graphName: 'ComplianceGSN' })` çağrısı ile DOT içeriğini üretin.
3. Dönen değeri `reports/compliance-gsn.dot` benzeri bir dosyaya yazın ve `dot -Tsvg reports/compliance-gsn.dot -o reports/compliance-gsn.svg` komutu ile görseli üretin.
4. Grafikteki lejant kanıt/boşluk düğümlerini, bağımsızlık kenar kalınlıklarını ve SOI kümelerini açıklar; böylece denetçiler hangi hedeflerin hangi kanıtlarla desteklendiğini ve hangi artefaktların eksik/stale kaldığını tek bakışta görebilir.

DOT çıktısı varsayılan olarak tüm boşluk kategorilerini (plan/test/coverage vb.) ve `snapshot.gaps.staleEvidence` içindeki yaş aşımı veya snapshot'tan eski kanıt bulgularını kırmızı kalıntı düğümleri olarak gösterir. Bağımsızlık eksikliği bulunan hedefler için ayrıca “Bağımsızlık Eksikliği” lejantı, kalınlaştırılmış kenarlar ve düğüm etiketindeki “Bağımsızlık: …” satırı üretilir. CI pipeline'ı bu çıktıyı golden test ile doğruladığından, yeni hedefler eklendiğinde `UPDATE_GOLDENS=1 npm run test --workspace @soipack/report -- gsn` komutu ile güncel DOT şablonunu yakalayabilirsiniz.

### Değişiklik etki analizi

Uyum matrisi ve kapsam raporu, snapshot değişiklik etkisi verisi içerdiğinde "Değişiklik Etki Analizi" adlı yeni bir bölüm ekler. Bölüm, uyum tablosunun hemen ardından yer alır ve signoff zaman çizelgesi gibi takip eden panellerden önce gösterilir; böylece denetçiler önce öncelikli değişiklikleri gözden geçirip ardından onay akışına geçebilir.【F:packages/report/src/index.ts†L2915-L3211】

Şablon, en yüksek şiddet değerine sahip kayıtları sınırlandırıp (varsayılan 25) rozetlerle özetleyen bir üst bilgi üretir. Özet satırı toplam kayıt sayısını, kritik/yüksek/orta seviyelerdeki dağılımı ve her seviyenin renk kodlu sınıflarını gösterir; satır içindeki tablo ise öğe kimliği, düğüm türü, yüzde olarak şiddet değeri ve durum rozetleriyle gerekçe özetini içerir. Çok sayıda gerekçe kısa biçimde birleştirilir ve kalan sayısı parantez içinde belirtilir.【F:packages/report/src/index.ts†L2640-L2730】【F:packages/report/src/complianceReport.html.ts†L145-L189】

Aynı veri kümeleri JSON çıktısına da eklenir; `compliance-matrix.json` dosyası `changeImpact` alanını taşırken özet metrikler değişiklik etkisi bulunan snapshot'larda toplam kayıt sayısını gösterir. PDF çıktısı HTML bölümünü yeniden kullandığından, rozet renkleri ve aria öznitelikleri erişilebilirlik gereksinimlerini de korur.【F:packages/report/src/index.ts†L2753-L3083】

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

## Ledger raporu CLI komutu

`soipack ledger-report` komutu, iki manifest arasındaki ledger farkını `@soipack/report` şablonlarıyla PDF’e dönüştürür. Komut referans (`--base`) ve hedef (`--target`) manifest yollarını alır, farkı hesaplamak için ledger kanıtlarını doğrular ve çıktı dizinine (`--output`) `ledger-report.pdf` dosyasını yazar. Rapor; manifest özet metriklerini, Merkle/ledger köklerini, değişen kanıtları ve ilgili dosyaların Merkle kanıtlarını tek sayfada sunar.

Opsiyonel `--title` başlığı ile rapor üst bilgisini özelleştirebilir, `--signing-key` bayrağıyla da var olan Ed25519 özel anahtarı kullanarak PDF’i imzalayabilirsiniz. İmza başarıyla üretildiğinde aynı dizine `ledger-report.pdf.sig` dosyası yazılır ve base64 imza gövdesi rapor çıktısında da raporlanır. Böylece denetçiler manifest farkını inceleyen PDF’in hash’ini (`sha256`) ve imzasını dış sistemlerde doğrulayabilir.
