# Kapsam Toplayıcıları

SOIPack motoru, farklı kapsama çıktılarından birleşik özetler üretmek için `CoverageAggregator` yardımcılarını sağlar. Toplayıcılar statement, dallanma ve MC/DC metriklerini normalize eder, sonuçları `CoverageReport` şemasına dönüştürür ve kullanıcıları eksik veriler konusunda bilgilendirir.

## Desteklenen kaynak formatları

- **JSON yapılandırılmış kapsam** – Her dosya için satır, dallanma ve MC/DC girişlerini içeren ayrıntılı bir JSON belgesi kabul edilir. Satır düzeyindeki kayıtlar `hit` alanıyla işaretlenir ve dallanma/MC/DC girdileri kapsanan ve toplam sayıları belirtir.
- **Cobertura XML** – Standart Cobertura `<coverage>` çıktılarından satır ve karar kapsamı çıkarılır. `condition-coverage="50% (1/2)"` gibi öznitelikler karar kapsam oranlarını belirlemek için ayrıştırılır.

Her iki içe aktarım da dosya yollarını normalize eder ve sonuçları motorun diğer bileşenlerinde kullanılan `CoverageReport` tipine dönüştürür. Böylece izlenebilirlik raporları ve kalite kontrolleri tek bir kapsama temsilinden beslenir.

## Hesaplama yöntemi

Toplayıcılar tüm metrikleri 0,1 hassasiyetinde hesaplar:

1. Her dosyanın satır girişlerinden toplam ve kapsanan satır sayısı çıkarılır.
2. Dallanma ve MC/DC girdileri varsa toplanır; toplam 0 ise metrikler rapordan çıkarılır.
3. Dosya metrikleri `covered / total` değerleri kullanılarak yüzdeye çevrilir ve `toFixed(1)` ile yuvarlanır.
4. Tüm dosyalar üzerinden küresel toplamlar hesaplanır ve aynı hassasiyetle raporlanır.

## Satır aralıklarının yok sayılması

Toplayıcı fonksiyonları `ignore` seçeneği ile dosya bazlı satır aralıklarını dışarıda bırakabilir. Aralıklar başlangıç ve bitiş satırı ile tanımlanır; belirtilen aralıktaki satırlar hem dosya özetinden hem de küresel toplamlardan çıkarılır. Bu yetenek, oluşturulmamış kod bloklarını veya analiz kapsamı dışında bırakılan yardımcıları filtrelemek için kullanılır.

## Uyarılar

MC/DC verisi sağlamayan girdiler kullanıcıya açık uyarılar üretir. JSON içe aktarımında MC/DC dizisi olmayan her dosya için bir uyarı döner; Cobertura raporları ise MC/DC desteği sunmadığı için her dosya için ve rapor genelinde ek bilgilendirme mesajları üretir. Toplamlarda MC/DC metriği bulunmuyorsa “MC/DC kapsam verisi raporda bulunamadı.” mesajı eklenir. Bu uyarılar raporlama katmanında görünür ve doğrulama sürecinde eksik metriklerin fark edilmesini sağlar.
