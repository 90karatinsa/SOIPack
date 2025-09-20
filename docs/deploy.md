# Air-Gapped SOIPack Sunucu Dağıtımı

Bu belge, internet bağlantısı olmayan ("air-gapped") ortamlarda SOIPack REST API sunucusunu Docker ile çalıştırmak için izlenmesi gereken adımları açıklar. Süreç iki aşamadan oluşur: internet erişimi olan hazırlık makinesi ve hedef air-gapped ortam.

## 1. Hazırlık Makinesinde İmajı Oluşturma

1. Gerekli araçları yükleyin:
   - Docker 24+
   - Docker Compose plugin
   - Git
2. Kaynak kodunu klonlayın ve dizine girin:
   ```bash
   git clone https://github.com/<kurumunuz>/SOIPack.git
   cd SOIPack
   ```
3. Üretim derlemesini hazırlayın. Bu adım, çok-aşamalı Docker imajında da çalıştırıldığı için Playwright tarayıcıları dâhil tüm bağımlılıkları indirir:
   ```bash
   npm ci
   npm run build
   ```
4. Konteyner imajını oluşturun:
   ```bash
   docker build -t soipack/server:latest .
   ```
5. İmajı air-gapped ortama taşıyabilmek için dışa aktarın:
   ```bash
   docker save soipack/server:latest | gzip > soipack-server.tar.gz
   ```
6. Kurum içi registry'e yüklemeniz gerekiyorsa imajı etiketleyip push edin:
   ```bash
   docker tag soipack/server:latest registry.example.com/soipack/server:v0.1.0
   docker push registry.example.com/soipack/server:v0.1.0
   ```
   Yukarıdaki `registry.example.com` ve etiket değerlerini kendi ortamınıza göre güncelleyin.
7. Aşağıdaki dosyaları hedef ortama kopyalayın:
   - `soipack-server.tar.gz`
   - `docker-compose.yaml`
   - `.env.example` yerine oluşturacağınız `.env` dosyası için şablon (aşağıya bakın)
   - `data/` dizini (hedefte kalıcı depolama için aynı yolu kullanacağız)
   - Örnek veri setleri (isteğe bağlı olarak `examples/minimal/`)

> **Not:** Docker imajı Playwright'ın `chromium` motoru ve ilgili sistem paketleriyle birlikte gelir. Air-gapped ortamda ek bağımlılık indirmenize gerek yoktur.

## 2. Air-Gapped Ortamda Kurulum

1. Dosyaları hedef makinede uygun bir klasöre çıkarın ve `data/` dizininin bulunduğundan emin olun:
   ```bash
   tar -xzf soipack-server.tar.gz
   ls data/objectives/do178c_objectives.min.json
   ```
2. Docker imajını içe aktarın:
   ```bash
   docker load < soipack-server.tar.gz
   ```
3. Sunucunun ihtiyaç duyduğu ortam değişkenlerini tanımlayın. JSON Web Token doğrulaması için OpenID Connect uyumlu bir sağlayıcının `issuer`, `audience` ve JWKS uç noktası belirtilmelidir. Aynı klasörde bir `.env` dosyası oluşturun:
   ```bash
   cat <<'ENV' > .env
   SOIPACK_AUTH_ISSUER=https://kimlik.example.com/
   SOIPACK_AUTH_AUDIENCE=soipack-api
   SOIPACK_AUTH_JWKS_URI=https://kimlik.example.com/.well-known/jwks.json
   # İsteğe bağlı claim eşlemesi ve kapsam gereksinimleri
   SOIPACK_AUTH_TENANT_CLAIM=tenant
   SOIPACK_AUTH_USER_CLAIM=sub
   SOIPACK_AUTH_REQUIRED_SCOPES=soipack.api
   # Sağlık kontrolü için uzun ömürlü bir JWT sağlayın (opsiyonel)
   SOIPACK_HEALTHCHECK_TOKEN=
   PORT=3000
   SOIPACK_STORAGE_DIR=/data/soipack
   SOIPACK_SIGNING_KEY_PATH=/run/secrets/soipack-signing.pem
   # Antivirüs komut satırı entegrasyonu (örn. ClamAV)
   SOIPACK_SCAN_COMMAND=/usr/bin/clamdscan
   SOIPACK_SCAN_ARGS=--fdpass,--no-summary
   SOIPACK_SCAN_TIMEOUT_MS=60000
   SOIPACK_SCAN_INFECTED_EXIT_CODES=1
   # Eski çıktıları otomatik temizlemek için gün bazında saklama süreleri (opsiyonel)
   SOIPACK_RETENTION_UPLOADS_DAYS=14
   SOIPACK_RETENTION_ANALYSES_DAYS=30
   SOIPACK_RETENTION_REPORTS_DAYS=30
   SOIPACK_RETENTION_PACKAGES_DAYS=60
   ENV
   ```
4. Kalıcı depolama için `data/` dizinini kullanarak servisi başlatın:
   ```bash
   docker compose up -d
   ```
5. Sağlık kontrolünü doğrulayın (geçerli bir JWT üretmek için OIDC sağlayıcınızı kullanın):
   ```bash
   docker compose ps
   TOKEN=$(./jwt-olustur.sh) # örnek: kendi betiğiniz veya sağlayıcı SDK'sı
   curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/health
   ```

Sunucu sağlıklı dönerse çıktı `{"status":"ok"}` olacaktır. Tüm iş çıktıları (yüklemeler, analizler, raporlar ve paketler) varsayılan olarak `data/` dizininde saklanır ve konteyner yeniden başlatıldığında korunur. Dosya tabanlı depolama yerine PostgreSQL/S3 gibi alternatifleri tercih ediyorsanız `packages/server/src/storage.ts` altında tanımlı `StorageProvider` arayüzünü uygulayarak `createServer` fonksiyonuna özel bir sağlayıcı enjekte edebilirsiniz.

## 3. Örnek Pipeline Çağrısı

Aşağıdaki örnek, `examples/minimal/` dizinindeki demo verilerini kullanarak uçtan uca PDF raporu oluşturur. Komutları çalıştırmadan önce geçerli bir JWT üretip `TOKEN` değişkenini ayarlayın:

```bash
TOKEN=$(./jwt-olustur.sh)
BASE_URL=http://localhost:3000
```

1. Gereken demo dosyalarını içeren bir import isteği gönderin:
   ```bash
   curl -X POST "$BASE_URL/v1/import" \
     -H "Authorization: Bearer $TOKEN" \
     -F "projectName=SOIPack Demo" \
     -F "projectVersion=1.0" \
     -F "level=C" \
     -F "reqif=@examples/minimal/spec.reqif" \
     -F "junit=@examples/minimal/results.xml" \
     -F "lcov=@examples/minimal/lcov.info" \
     -F "cobertura=@examples/minimal/coverage.xml" \
     -F "objectives=@data/objectives/do178c_objectives.min.json"
   ```
   Dönen JSON içindeki `id` alanını `IMPORT_ID` olarak saklayın.

2. Analiz isteği gönderin:
   ```bash
   curl -X POST "$BASE_URL/v1/analyze" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"importId\":\"$IMPORT_ID\"}"
   ```
   Yanıttaki `id` değerini `ANALYSIS_ID` olarak kaydedin.

3. Rapor üretin (PDF ve HTML çıktıları bu adımda oluşur):
   ```bash
   curl -X POST "$BASE_URL/v1/report" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"analysisId\":\"$ANALYSIS_ID\"}"
   ```
   Yanıttaki `outputs.directory` alanı, `data/` altında oluşturulan rapor klasörünü gösterir. Örneğin `data/reports/<rapor-id>/compliance_matrix.pdf` dosyasını açarak PDF üretimini doğrulayabilirsiniz.

4. (İsteğe bağlı) Raporu paketleyin ve arşiv/manifesti indirin:
   ```bash
   curl -X POST "$BASE_URL/v1/pack" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"reportId\":\"<rapor-id>\"}"
   ```

   Yanıtın `id` alanını `PACKAGE_ID` olarak kaydedin. Paket arşivi ile manifesti JWT kimlik doğrulamasıyla çekmek için:

   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     "$BASE_URL/v1/packages/$PACKAGE_ID/archive" \
     --output soipack-$PACKAGE_ID.zip

   curl -H "Authorization: Bearer $TOKEN" \
     "$BASE_URL/v1/packages/$PACKAGE_ID/manifest" \
     --output manifest-$PACKAGE_ID.json
   ```

   Aynı işlem CLI üzerinden de yapılabilir:

   ```bash
   node packages/cli/dist/index.js download \
     --api "$BASE_URL" \
     --token "$TOKEN" \
     --package "$PACKAGE_ID" \
     --output artifacts/
   ```

   Arşiv içinde yer alan `manifest.sig` dosyası ile indirilen manifesti teslimat öncesinde doğrulamak için:

   ```bash
   unzip artifacts/soipack-$PACKAGE_ID.zip manifest.sig
   node packages/cli/dist/index.js verify \
     --manifest manifest-$PACKAGE_ID.json \
     --signature manifest.sig \
     --public-key path/to/ed25519_public.pem
   ```

## 4. Güncelleme ve Bakım

- Yeni bir sürüm yayınlandığında, hazırlık makinesinde `docker build` ve `docker save` adımlarını tekrar ederek yeni imajı içe aktarın.
- Kalıcı `data/` klasörünü düzenli olarak yedekleyin.
- `docker compose logs -f server` komutu ile hata ayıklama günlüklerini takip edebilirsiniz.
- Saklama politikaları ayarlıysa (örn. `SOIPACK_RETENTION_*_DAYS`), eski iş çıktıları `POST /v1/admin/cleanup` çağrısıyla temizlenir. JSON yanıtı hangi dizinlerden kaç kaydın silindiğini gösterir.

## 5. Gözlemlenebilirlik

- Sunucu varsayılan olarak [Pino](https://getpino.io) tabanlı JSON günlükleri üretir. Her iş için aşağıdaki olaylar yazılır:
  - `job_created`: Kuyruğa yeni iş eklendiğinde.
  - `job_completed`: Pipeline başarıyla tamamlandığında (süre ms cinsinden `durationMs`).
  - `job_reused`: Aynı parametrelerle oluşturulmuş önceki bir iş yeniden kullanıldığında.
  - `job_failed`: İş çalışırken hata aldığında (HTTP hata kodu ve ayrıntılar dahil).
  Bu günlükleri `docker compose logs -f server` veya kendi log toplayıcınıza yönlendirerek inceleyebilirsiniz.
- Prometheus uyumlu metrikler `/metrics` uç noktasından sunulur ve diğer API çağrıları gibi JWT ile kimlik doğrulaması gerektirir:
  ```bash
  curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/metrics
  ```
  Başlıca metrikler:
  - `soipack_job_duration_seconds{tenantId,kind,status}`: Her iş türü için tamamlanma/başarısızlık süre histogramı.
  - `soipack_job_queue_depth{tenantId}`: Kuyrukta bekleyen veya çalışan iş sayısı.
  - `soipack_job_errors_total{tenantId,kind,code}`: Hata koduna göre başarısız işlerin sayısı.
  Varsayılan Prometheus registry’si süreç istatistiklerini de içerir. Dışarıdan bir Prometheus sunucusu bu uç noktayı scrape ederek panolar oluşturabilir.

Bu adımlar tamamlandığında air-gapped ortamda `docker compose up -d` komutuyla SOIPack API'si PDF/rapor üretecek şekilde hazır olacaktır.

## 6. Dosya Taraması ve Antivirüs Servisi

- Sunucu, yüklenen her dosyayı kalıcı depolamaya taşımadan önce geçici bir dizine (örn. `/tmp/soipack-upload-*`) yazar ve içerik türü/payload boyutlarını alan bazında doğrular.
- `SOIPACK_SCAN_COMMAND` ortam değişkeni tanımlandığında her dosya bu komuta parametre olarak **dosya yoluyla** iletilir. Komut 0 ile dönerse yükleme temiz kabul edilir, `SOIPACK_SCAN_INFECTED_EXIT_CODES` listesindeki kodlardan biri ile dönerse yükleme tehdit olarak işaretlenir ve HTTP 422 hatası verilir.
- Tarama komutu zaman aşımına uğrarsa veya 0/tehdit kodları dışında bir çıkış kodu üretirse istek HTTP 502 hatasıyla reddedilir. Varsayılan zaman aşımı `SOIPACK_SCAN_TIMEOUT_MS` değeri ile milisaniye cinsinden yapılandırılabilir.
- `SOIPACK_SCAN_ARGS` listesinde (virgül ile ayrılmış) belirtilen ek parametreler her çağrıda komuta iletilir. ClamAV için önerilen değerler: `SOIPACK_SCAN_COMMAND=/usr/bin/clamdscan` ve `SOIPACK_SCAN_ARGS=--fdpass,--no-summary`.
- Tarama servisinin `SOIPACK` konteyneri tarafından erişilebilir olması, gerekli imza/güncelleme işlemlerinin operasyon ekiplerince yönetilmesi ve yükleme başına en fazla dosya boyutu limitlerini (örn. lisans dosyaları için 512 KB, analiz girdileri için 25 MB) karşılayacak performansı sağlaması gerekir.
