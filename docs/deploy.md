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
3. TypeScript kaynaklarını derleyin. Bu adım, çok-aşamalı Docker imajının builder katmanında da çalıştırılan `npm ci` ve `npm run build` komutlarıyla `packages/**/dist` çıktısını hazırlar:
   ```bash
   npm ci
   npm run build
   ```
4. Konteyner imajını oluşturun. Oluşturulan imaj, builder katmanından yalnızca derlenmiş çıktıları (`packages/**/dist`), `data/` altındaki paylaşılan veri dosyalarını ve gereken yapılandırmaları kopyalar; çalışma zamanı girdisi `node packages/server/dist/start.js` olarak tanımlıdır:
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

> **Not:** Çalışma zamanı imajı Playwright tarayıcılarını içermez; `npm ci --omit=dev` ile yalnızca üretim bağımlılıkları yüklenir ve TypeScript kaynaklarının yerine derlenmiş paketler kullanılır. Bu sayede air-gapped ortamda ek bağımlılık indirmeniz gerekmez ve imaj boyutu küçülür.

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
3. Sunucunun imza anahtarını, lisans doğrulama anahtarını ve TLS sertifikalarını `secrets/` dizinine kopyalayın. Docker Compose yapılandırması, dosya adlarının sırasıyla `soipack-signing.pem`, `soipack-license.pub`, `soipack-tls.key` ve `soipack-tls.crt` olmasını bekler. Sunucu yalnızca TLS 1.2 ve üzeri istemcileri kabul eder; modern AES-GCM/CHACHA20 paketlerinden oluşan sabit bir şifre kümesiyle ve TLS yeniden görüşmesini devre dışı bırakarak bağlantıyı sertleştirir. Yönetici uç noktaları için istemci sertifikası doğrulaması kullanılacaksa güvenilir istemci sertifika otoritesini `soipack-client-ca.pem` adıyla aynı dizine yerleştirin. Bu değer tanımlandığında istemci sertifikası zorunlu hâle gelir ve sertifika sunamayan veya CA ile doğrulanmayan istemciler TLS el sıkışmasında reddedilir. HTTP isteklerinde kullanılacak lisans dosyasını `license.key` adıyla saklayın:
   ```bash
   mkdir -p secrets
   cp /path/to/soipack-signing.pem secrets/soipack-signing.pem
   cp /path/to/soipack-license.pub secrets/soipack-license.pub
   cp /path/to/tls/server.key secrets/soipack-tls.key
   cp /path/to/tls/server.crt secrets/soipack-tls.crt
   # Sağlık kontrolü ve Compose healthcheck'i için güvenilir sunucu CA'sı
   cp /path/to/tls/ca.crt secrets/soipack-ca.crt
   # İsteğe bağlı: yönetici uçları için istemci CA sertifikası
   # cp /path/to/clients/ca.crt secrets/soipack-client-ca.pem
   cp /path/to/license.key license.key
   ```

   HTTPS dinleyicisi varsayılan olarak `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options` ve benzeri HTTP başlıklarını göndererek kullanıcı arayüzleri ve API çağrıları için güvenli varsayılanlar uygular; Express'in `X-Powered-By` başlığı devre dışı bırakılmıştır. Tüm istemcilerin bu başlıklara hazır olduğundan emin olun ve TLS sonlandırmasını başka bir katmanda yapıyorsanız aynı güvenlik başlıklarını orada da çoğaltın.
4. Sunucunun ihtiyaç duyduğu ortam değişkenlerini tanımlayın. JSON Web Token doğrulaması için OpenID Connect uyumlu bir sağlayıcının `issuer`, `audience` ve JWKS uç noktası belirtilmelidir. Aynı klasörde bir `.env` dosyası oluşturun:
   ```bash
   cat <<'ENV' > .env
   SOIPACK_AUTH_ISSUER=https://kimlik.example.com/
   SOIPACK_AUTH_AUDIENCE=soipack-api
   SOIPACK_AUTH_JWKS_URI=https://kimlik.example.com/.well-known/jwks.json
   # Alternatif olarak JWKS'i dosyadan okuyun
   # SOIPACK_AUTH_JWKS_PATH=/run/secrets/oidc-jwks.json
   # İsteğe bağlı claim eşlemesi ve kapsam gereksinimleri
   SOIPACK_AUTH_TENANT_CLAIM=tenant
   SOIPACK_AUTH_USER_CLAIM=sub
   SOIPACK_AUTH_REQUIRED_SCOPES=soipack.api
   SOIPACK_AUTH_ADMIN_SCOPES=soipack.admin
   # Sağlık kontrolü için zorunlu bearer token (örn. uzun ömürlü JWT)
   SOIPACK_HEALTHCHECK_TOKEN=
   PORT=3443
   SOIPACK_STORAGE_DIR=/data/soipack
   SOIPACK_SIGNING_KEY_PATH=/run/secrets/soipack-signing.pem
   SOIPACK_LICENSE_PUBLIC_KEY_PATH=/run/secrets/soipack-license.pub
   SOIPACK_LICENSE_MAX_BYTES=524288
   SOIPACK_LICENSE_HEADER_MAX_BYTES=699051
   SOIPACK_LICENSE_CACHE_MAX_ENTRIES=1024
   SOIPACK_LICENSE_CACHE_MAX_AGE_MS=3600000
   SOIPACK_TLS_KEY_PATH=/run/secrets/soipack-tls.key
   SOIPACK_TLS_CERT_PATH=/run/secrets/soipack-tls.crt
   # İsteğe bağlı: yönetici uçları için istemci CA sertifikası
   SOIPACK_TLS_CLIENT_CA_PATH=/run/secrets/soipack-client-ca.pem
   SOIPACK_MAX_JSON_BODY_BYTES=2097152
   SOIPACK_RATE_LIMIT_IP_WINDOW_MS=60000
   SOIPACK_RATE_LIMIT_IP_MAX_REQUESTS=300
   SOIPACK_RATE_LIMIT_IP_MAX_KEYS=10000
   SOIPACK_RATE_LIMIT_TENANT_WINDOW_MS=60000
   SOIPACK_RATE_LIMIT_TENANT_MAX_REQUESTS=150
   SOIPACK_RATE_LIMIT_TENANT_MAX_KEYS=10000
   # Reverse proxy arkasında gerçek istemci IP'lerini kullanmak için true/loopback/127.0.0.1/8 gibi değerler
   SOIPACK_TRUST_PROXY=false
   # Kiracı başına kuyruğa alınan/çalışan iş limiti (opsiyonel, varsayılan 5)
   SOIPACK_MAX_QUEUED_JOBS=5
   # Tüm kiracılar için global kuyruğa alınan iş limiti (opsiyonel)
   SOIPACK_MAX_QUEUED_JOBS_TOTAL=20
   # Aynı anda çalıştırılabilecek iş sayısı (opsiyonel, varsayılan 1)
   SOIPACK_WORKER_CONCURRENCY=2
   # Antivirüs komut satırı entegrasyonu (örn. ClamAV)
   SOIPACK_SCAN_COMMAND=/usr/bin/clamdscan
   SOIPACK_SCAN_ARGS=--fdpass,--no-summary
   SOIPACK_SCAN_TIMEOUT_MS=60000
   SOIPACK_SCAN_INFECTED_EXIT_CODES=1
   SOIPACK_HTTP_REQUEST_TIMEOUT_MS=300000
   SOIPACK_HTTP_HEADERS_TIMEOUT_MS=60000
   SOIPACK_HTTP_KEEP_ALIVE_TIMEOUT_MS=5000
   SOIPACK_SHUTDOWN_TIMEOUT_MS=30000
   # Eski çıktıları otomatik temizlemek için gün bazında saklama süreleri (opsiyonel)
   SOIPACK_RETENTION_UPLOADS_DAYS=14
   SOIPACK_RETENTION_ANALYSES_DAYS=30
   SOIPACK_RETENTION_REPORTS_DAYS=30
   SOIPACK_RETENTION_PACKAGES_DAYS=60
   # Saklama temizliğini otomatik tetiklemek için periyot (ms)
   SOIPACK_RETENTION_SWEEP_INTERVAL_MS=900000
   ENV
   ```

   `SOIPACK_AUTH_ADMIN_SCOPES`, virgülle ayrılmış yönetici kapsamlarını tanımlar. Liste boş değilse yalnızca bu kapsamların en az birine sahip belirteçler yönetici uç noktalarına (`POST /v1/admin/cleanup` ve `/metrics`) erişebilir. İş yüklerini tetikleyen kullanıcılarla gözlemleme/bakım ekiplerini ayrıştırmak için ayrı bir erişim scope'u tanımlamanız önerilir.

   `SOIPACK_AUTH_JWKS_URI` değeri yalnızca HTTPS protokolünü kabul eder; air-gap senaryosunda JWKS içeriğini önceden indirip `SOIPACK_AUTH_JWKS_PATH` ile dosya sisteminden paylaşabilirsiniz. Uzak JWKS yanıtlarının zaman aşımına uğramaması için varsayılan değerler 5 saniyelik zaman aşımı, sınırlı tekrar denemeleri ve önbellekleme davranışı içerir; ortamınızın gereksinimlerine göre `SOIPACK_AUTH_JWKS_TIMEOUT_MS` ve ilgili değişkenlerle bu süreleri ayarlayabilirsiniz.

   `SOIPACK_SIGNING_KEY_PATH` ve `SOIPACK_LICENSE_PUBLIC_KEY_PATH` değerleri, üçüncü adımda oluşturduğunuz `/run/secrets` bağlamasındaki `soipack-signing.pem` ve `soipack-license.pub` dosyalarına işaret eder. `SOIPACK_TLS_KEY_PATH` ve `SOIPACK_TLS_CERT_PATH` ise HTTPS dinleyicisi için sunucu anahtarı ile sertifikasını gösterir; bu dosyalar okunamazsa hizmet başlatılmaz. Yönetici uç noktaları için istemci sertifikası zorunlu tutulacaksa `SOIPACK_TLS_CLIENT_CA_PATH` değerini güvenilir kök sertifika otoritesiyle birlikte tanımlayın; aksi halde bu değişken boş bırakılmalıdır. `SOIPACK_HEALTHCHECK_CA_PATH` değeri varsayılan olarak `/run/secrets/soipack-ca.crt` yolunu kullanır ve hem Docker Compose healthcheck komutunun hem de `scripts/verify-healthcheck.js` betiğinin kendine imzalı sertifikaları doğrulamasını sağlar. `SOIPACK_HEALTHCHECK_TOKEN` boş bırakılamaz; konteynerdeki sağlık kontrolü komutu aynı bearer token'ı kullanır ve sunucu bu değer tanımlandığında `/health` uç noktasına gelen isteklerin `Authorization: Bearer <token>` başlığını içermesini zorunlu kılar. Başlık eksik ya da hatalıysa API `401 UNAUTHORIZED` döner.

   Sunucu başlatma betiği, `SOIPACK_SIGNING_KEY_PATH` tarafından işaret edilen PEM dosyasının okunabilirliğini baştan doğrular. Dosya yanlış bağlanmışsa veya izinler sebebiyle erişilemiyorsa hizmet `SOIPACK_SIGNING_KEY_PATH ile belirtilen anahtar dosyasına erişilemiyor` hatasıyla hemen durur.

  Tüm HTTPS istekleri için lisans dosyasını base64'e çevirerek `X-SOIPACK-License` başlığına ekleyin. Örneklerde kullanılan `license.key`, lisans sağlayıcısından aldığınız JSON dosyasının ham halidir. Lisans içeriği `SOIPACK_LICENSE_MAX_BYTES` ile sınırlıdır; başlıkta gönderilen base64 verisi `SOIPACK_LICENSE_HEADER_MAX_BYTES` üstüne çıkarsa veya çözülmüş hali sınırı aşarsa sunucu `413 LICENSE_TOO_LARGE` döndürür. Büyük `license` form alanları belleğe yüklenmez, sınır aşıldığında akış diske taşınmadan önce kesilir ve aynı hata kodu döner. Bu değerleri yükseltmeniz gerekiyorsa sınırlarınızı eş zamanlı olarak güncelleyin.

  Lisans anahtarında bulunan `features` listesi, istemcinin hangi pipeline uç noktalarını çağırabileceğini belirler. Sırasıyla `/v1/import`, `/v1/analyze`, `/v1/report` ve `/v1/pack` uç noktaları `import`, `analyze`, `report` ve `pack` özelliklerine ihtiyaç duyar; gerekli özellik eksikse sunucu istekleri `403 LICENSE_FEATURE_REQUIRED` yanıtıyla reddeder.

  Lisans doğrulama yanıtları, tekrar eden istemcilerin gecikmesini azaltmak için `SOIPACK_LICENSE_CACHE_MAX_ENTRIES` ve `SOIPACK_LICENSE_CACHE_MAX_AGE_MS` ile sınırlı bellek önbelleğinde tutulur. Varsayılanlar sırasıyla 1024 kayıt ve 1 saat olup, yeni kiracılar eklendikçe önbellek en eski girişleri otomatik temizler. Bellek tüketimini yakından izliyorsanız, cache büyüklüğünü ortamınızın kullanıcı sayısına göre ayarlayın.

  JSON gövde boyutu (`SOIPACK_MAX_JSON_BODY_BYTES`) ve oran sınırlaması (`SOIPACK_RATE_LIMIT_*` değişkenleri) varsayılan olarak hizmet kötüye kullanımına karşı koruma sağlar. Değerler milisaniye ve istek sayısı cinsinden ayarlanabilir. Her pencere için benzersiz IP/kiralayan girişlerinin bellekte tutulacağı üst sınırı `SOIPACK_RATE_LIMIT_IP_MAX_KEYS` ve `SOIPACK_RATE_LIMIT_TENANT_MAX_KEYS` ile belirleyebilirsiniz; sınır aşıldığında en eski sayaçlar otomatik olarak düşürülür ve pencere süresi sona erdiğinde temizlenir. Bu davranış, saldırganların sahte IP'lerle sınırsız sayaç biriktirmesini engeller.

  Kuyruk limitleri iki seviyede yapılandırılabilir. `SOIPACK_MAX_QUEUED_JOBS`, her kiracı için eşzamanlı olarak kuyruğa alınan veya çalışan işlerin üst sınırını belirler (varsayılan 5). `SOIPACK_MAX_QUEUED_JOBS_TOTAL` tanımlandığında aynı zamanda tüm kiracılar için global bir üst sınır uygulanır; toplam limit aşıldığında API `429 QUEUE_LIMIT_EXCEEDED` hatası döner ve hata detaylarında `scope: "global"` bilgisi yer alır. `SOIPACK_WORKER_CONCURRENCY` ise arka planda aynı anda kaç işin çalıştırılacağını belirler. Bu değeri CPU çekirdek sayınıza göre ayarlayarak paralel import/analiz yürütmelerini hızlandırabilir, ancak disk ve bellek tüketimini yakından izlemelisiniz. Limitlerden herhangi biri aşıldığında sunucu yeni işleri kuyruğa almaz; istemciler mevcut işlerden biri tamamlandıktan sonra yeniden denemelidir.

  API'nin bir ters proxy arkasında çalıştığı dağıtımlarda, istemci IP'lerinin `X-Forwarded-For` başlığından alınabilmesi ve oran sınırlamasının doğru IP'ler üzerinde uygulanması için `SOIPACK_TRUST_PROXY` değerini uygun şekilde (örneğin `true`, `loopback` veya CIDR bloğu) ayarlayın.

### Zarif kapatma ve zaman aşımı kontrolleri

Sunucu `SIGTERM` veya `SIGINT` aldığında yeni bağlantıları durdurur, bekleyen HTTP isteklerinin `server.close()` ile tamamlanmasını bekler ve kuyruktaki işler için `SOIPACK_SHUTDOWN_TIMEOUT_MS` süresi boyunca `waitForIdle` çağrılarıyla boşalmayı bekler. Kuyruklar bu süre içinde tamamlanmazsa kalan işler iptal edilir ve süreç temiz şekilde sonlandırılır. Bu davranışın sorunsuz işlemesi için orkestrasyon aracınız (Docker, systemd vb.) yeterli kapanış süresi tanımalıdır.

`SOIPACK_HTTP_REQUEST_TIMEOUT_MS`, `SOIPACK_HTTP_HEADERS_TIMEOUT_MS` ve `SOIPACK_HTTP_KEEP_ALIVE_TIMEOUT_MS` değerleri sırasıyla HTTP isteklerinin, başlık müzakeresinin ve keep-alive bağlantılarının kapanma zamanlarını kontrol eder. Varsayılanlar çoğu kurulum için uygundur; uzun süre çalışan import yüklemeleri veya yavaş istemci ağları için değerleri artırabilirsiniz.

### Planlı saklama temizliği

`SOIPACK_RETENTION_*_DAYS` değişkenleri ile saklama pencereleri tanımlandığında, `SOIPACK_RETENTION_SWEEP_INTERVAL_MS` periyodu otomatik temizliği tetikler. Zamanlayıcı yalnızca en az bir hedef için saklama sınırı ayarlandığında devreye girer ve her turda tüm kiracılar için `POST /v1/admin/cleanup` ile aynı temizliği yürütür. Manuel çağrılar hâlâ desteklenir; ancak düzenli temizlik için konteynerin arka planda çalıştığından ve zamanlayıcıyı durduracak uyku modları olmadığından emin olun.
5. Kalıcı depolama için `data/` dizinini kullanarak servisi başlatın:
   ```bash
   docker compose up -d
   ```
6. Sağlık kontrolünü doğrulayın (geçerli bir JWT veya uzun ömürlü servis belirteci üretmek için OIDC sağlayıcınızı kullanın; `.env` dosyasındaki `SOIPACK_HEALTHCHECK_TOKEN` değerinin aynı olması gerekir). `scripts/verify-healthcheck.js` betiği Node.js içinde `NODE_EXTRA_CA_CERTS` ayarını geçici olarak yapılandırarak self-signed sertifikaları doğrular:
   ```bash
   docker compose ps
   TOKEN=$(./jwt-olustur.sh) # örnek: kendi betiğiniz veya sağlayıcı SDK'sı
   export SOIPACK_HEALTHCHECK_TOKEN=$TOKEN
   export SOIPACK_HEALTHCHECK_CA_PATH=$(pwd)/secrets/soipack-ca.crt
   node scripts/verify-healthcheck.js
   ```

Sunucu sağlıklı dönerse çıktı `{"status":"ok"}` olacaktır; yanlış veya eksik bearer başlığı `401 UNAUTHORIZED` sonucu verir. Tüm iş çıktıları (yüklemeler, analizler, raporlar ve paketler) varsayılan olarak `data/` dizininde saklanır ve konteyner yeniden başlatıldığında korunur. Aynı dizin altında oluşturulan `.queue/` klasörü, durdurulup yeniden başlatılan örneklerin kuyruk durumunu (bekleyen, çalışan veya tamamlanan işler) kalıcı olarak saklar; bu sayede bekleyen işler yeniden kuyruğa alınmadan devam eder. Dosya tabanlı depolama yerine PostgreSQL/S3 gibi alternatifleri tercih ediyorsanız `packages/server/src/storage.ts` altında tanımlı `StorageProvider` arayüzünü uygulayarak `createServer` fonksiyonuna özel bir sağlayıcı enjekte edebilirsiniz.

Kanıt yüklemeleri, uyum kayıtları ve dondurulmuş konfigürasyon sürümleri de aynı kalıcı dizinde `tenants/<tenantId>/` altındaki JSON dosyalarına yazılır. Sunucunun yeniden başlatılması durumunda aynı `SOIPACK_STORAGE_DIR` yolu yeniden bağlanırsa REST API bu dosyaları okuyarak önceki kanıtları, uyum raporlarını ve dondurulmuş snapshot sürümlerini otomatik olarak geri yükler. Kalıcı depolama ayrılmadığında veya dizin temizlendiğinde bu veriler kaybolur; bu nedenle üretim ortamlarında depolamanın dışarıya (örneğin bir volume ya da ağ paylaşımı) kalıcı şekilde bağlandığından emin olun.

## 3. Örnek Pipeline Çağrısı

Aşağıdaki örnek, `examples/minimal/` dizinindeki demo verilerini kullanarak uçtan uca PDF raporu oluşturur. Komutları çalıştırmadan önce geçerli bir JWT üretip `TOKEN` değişkenini ayarlayın:

```bash
TOKEN=$(./jwt-olustur.sh)
BASE_URL=https://localhost:3443
```

1. Gereken demo dosyalarını içeren bir import isteği gönderin:
   ```bash
   curl -X POST "$BASE_URL/v1/import" \
     -H "Authorization: Bearer $TOKEN" \
     -H "X-SOIPACK-License: $(base64 -w0 license.key)" \
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
     -H "X-SOIPACK-License: $(base64 -w0 license.key)" \
     -H "Content-Type: application/json" \
     -d "{\"importId\":\"$IMPORT_ID\"}"
   ```
   Yanıttaki `id` değerini `ANALYSIS_ID` olarak kaydedin.

3. Rapor üretin (PDF ve HTML çıktıları bu adımda oluşur):
   ```bash
   curl -X POST "$BASE_URL/v1/report" \
     -H "Authorization: Bearer $TOKEN" \
     -H "X-SOIPACK-License: $(base64 -w0 license.key)" \
     -H "Content-Type: application/json" \
     -d "{\"analysisId\":\"$ANALYSIS_ID\"}"
   ```
   Yanıttaki `outputs.directory` alanı, `data/` altında oluşturulan rapor klasörünü gösterir. Örneğin `data/reports/<rapor-id>/compliance_matrix.pdf` dosyasını açarak PDF üretimini doğrulayabilirsiniz.

4. (İsteğe bağlı) Raporu paketleyin ve arşiv/manifesti indirin:
   ```bash
   curl -X POST "$BASE_URL/v1/pack" \
     -H "Authorization: Bearer $TOKEN" \
     -H "X-SOIPACK-License: $(base64 -w0 license.key)" \
     -H "Content-Type: application/json" \
     -d "{\"reportId\":\"<rapor-id>\"}"
   ```

   İsteğe bağlı `packageName` alanı gönderilecekse değer yalnızca harf/rakam, nokta, alt çizgi veya tire içeren ve `.zip` ile biten düz bir dosya adı olmalıdır (ör. `release.zip`). Yol gezinme dizileri (`../hack.zip`) veya mutlak yollar reddedilir.

   Yanıtın `id` alanını `PACKAGE_ID` olarak kaydedin. Paket arşivi ile manifesti JWT kimlik doğrulamasıyla çekmek için:

   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     -H "X-SOIPACK-License: $(base64 -w0 license.key)" \
     "$BASE_URL/v1/packages/$PACKAGE_ID/archive" \
     --output soipack-$PACKAGE_ID.zip

   curl -H "Authorization: Bearer $TOKEN" \
     -H "X-SOIPACK-License: $(base64 -w0 license.key)" \
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

   CLI varsayılan olarak yalnızca HTTPS taban adreslerinden indirmeye izin verir; güvenli olmayan `http://` uç noktaları için geliştirici ortamlarında `--allow-insecure-http` bayrağını özellikle eklemeniz gerekir.

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
- Saklama politikaları ayarlıysa (örn. `SOIPACK_RETENTION_*_DAYS`), eski iş çıktıları `POST /v1/admin/cleanup` çağrısıyla temizlenir. Bu uç noktaya erişim için `SOIPACK_AUTH_ADMIN_SCOPES` listesindeki kapsamların en az biri gerekir. JSON yanıtı hangi dizinlerden kaç kaydın silindiğini gösterir.

## 5. Gözlemlenebilirlik

- Sunucu varsayılan olarak [Pino](https://getpino.io) tabanlı JSON günlükleri üretir. Her iş için aşağıdaki olaylar yazılır:
  - `job_created`: Kuyruğa yeni iş eklendiğinde.
  - `job_completed`: Pipeline başarıyla tamamlandığında (süre ms cinsinden `durationMs`).
  - `job_reused`: Aynı parametrelerle oluşturulmuş önceki bir iş yeniden kullanıldığında.
  - `job_failed`: İş çalışırken hata aldığında (HTTP hata kodu ve ayrıntılar dahil).
  Bu günlükleri `docker compose logs -f server` veya kendi log toplayıcınıza yönlendirerek inceleyebilirsiniz.
- Prometheus uyumlu metrikler `/metrics` uç noktasından sunulur ve diğer API çağrıları gibi, ayrıca `SOIPACK_AUTH_ADMIN_SCOPES` listesinden en az bir kapsam içeren bir JWT ile kimlik doğrulaması gerektirir:
  ```bash
  curl -H "Authorization: Bearer $TOKEN" \
    -H "X-SOIPACK-License: $(base64 -w0 license.key)" \
    http://localhost:3000/metrics
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
