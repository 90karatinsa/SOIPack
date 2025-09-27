# Kapsam Toplayıcıları

SOIPack motoru, farklı kapsama çıktılarından birleşik özetler üretmek için `CoverageAggregator` yardımcılarını sağlar. Toplayıcılar statement, fonksiyon, dallanma ve MC/DC metriklerini normalize eder, sonuçları `CoverageReport` şemasına dönüştürür ve kullanıcıları eksik veriler konusunda bilgilendirir.

## Desteklenen kaynak formatları

- **JSON yapılandırılmış kapsam** – Her dosya için satır, fonksiyon, dallanma ve MC/DC girişlerini içeren ayrıntılı bir JSON belgesi kabul edilir. Satır ve fonksiyon kayıtları `hit` alanıyla işaretlenir; dallanma/MC/DC girdileri kapsanan ve toplam sayıları belirtir.
- **Cobertura XML** – Standart Cobertura `<coverage>` çıktılarından satır, fonksiyon ve karar kapsamı çıkarılır. `condition-coverage="50% (1/2)"` gibi öznitelikler karar kapsam oranlarını belirlemek için ayrıştırılır. Method blokları, satır isabetlerine göre fonksiyon kapsamını hesaplamak için analiz edilir.

Her iki içe aktarım da dosya yollarını normalize eder ve sonuçları motorun diğer bileşenlerinde kullanılan `CoverageReport` tipine dönüştürür. Böylece izlenebilirlik raporları ve kalite kontrolleri tek bir kapsama temsilinden beslenir.

## Otomatik kanıt eşlemeleri

`runImport` komutu, kapsam raporlarında karar (branch) veya MC/DC metrikleri bulunduğunda bu değerleri otomatik olarak DO-178C kanıt türleriyle eşleştirir. LCOV ve Cobertura raporlarında dallanma metrikleri tespit edilirse `coverage_dec`, MC/DC metrikleri tespit edilirse `coverage_mcdc` kanıt girdileri oluşturulur. Yapısal kapsam sağlayan LDRA ve VectorCAST özetleri için de aynı eşleme geçerlidir; böylece farklı araçlardan gelen veriler tek bir çalışma alanında karar ve MC/DC kanıtı olarak saklanır.

## Hesaplama yöntemi

Toplayıcılar tüm metrikleri 0,1 hassasiyetinde hesaplar:

1. Her dosyanın satır girişlerinden toplam ve kapsanan satır sayısı çıkarılır.
2. Fonksiyon kayıtları, bağımsız `hit` değerleriyle kapsanan fonksiyon sayısını hesaplar.
3. Dallanma ve MC/DC girdileri varsa toplanır; toplam 0 ise metrikler rapordan çıkarılır.
4. Dosya metrikleri `covered / total` değerleri kullanılarak yüzdeye çevrilir ve `toFixed(1)` ile yuvarlanır.
4. Tüm dosyalar üzerinden küresel toplamlar hesaplanır ve aynı hassasiyetle raporlanır.

## Satır aralıklarının yok sayılması

Toplayıcı fonksiyonları `ignore` seçeneği ile dosya bazlı satır aralıklarını dışarıda bırakabilir. Aralıklar başlangıç ve bitiş satırı ile tanımlanır; belirtilen aralıktaki satırlar hem dosya özetinden hem de küresel toplamlardan çıkarılır. Bu yetenek, oluşturulmamış kod bloklarını veya analiz kapsamı dışında bırakılan yardımcıları filtrelemek için kullanılır.

## Uyarılar

Fonksiyon veya MC/DC verisi sağlamayan girdiler kullanıcıya açık uyarılar üretir. JSON içe aktarımında ilgili diziler eksik olduğunda dosya bazında uyarı döner; Cobertura raporları method bilgisi ya da MC/DC desteği sunmadığında her dosya için ve rapor genelinde ek bilgilendirme mesajları üretilir. Toplamlarda fonksiyon veya MC/DC metriği bulunmuyorsa sırasıyla “Fonksiyon kapsam verisi raporda bulunamadı.” ve “MC/DC kapsam verisi raporda bulunamadı.” mesajları eklenir. Bu uyarılar raporlama katmanında görünür ve doğrulama sürecinde eksik metriklerin fark edilmesini sağlar.
