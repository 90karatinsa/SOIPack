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
3. Sunucunun ihtiyaç duyduğu ortam değişkenlerini tanımlayın. `SOIPACK_API_TOKEN` zorunludur. Aynı klasörde bir `.env` dosyası oluşturun:
   ```bash
   cat <<'ENV' > .env
   SOIPACK_API_TOKEN=degiştir-beni
   PORT=3000
   ENV
   ```
4. Kalıcı depolama için `data/` dizinini kullanarak servisi başlatın:
   ```bash
   docker compose up -d
   ```
5. Sağlık kontrolünü doğrulayın:
   ```bash
   docker compose ps
   curl -H "Authorization: Bearer $SOIPACK_API_TOKEN" http://localhost:3000/health
   ```

Sunucu sağlıklı dönerse çıktı `{"status":"ok"}` olacaktır. Tüm iş çıktıları (yüklemeler, analizler, raporlar ve paketler) `data/` dizininde saklanır ve konteyner yeniden başlatıldığında korunur.

## 3. Örnek Pipeline Çağrısı

Aşağıdaki örnek, `examples/minimal/` dizinindeki demo verilerini kullanarak uçtan uca PDF raporu oluşturur. Komutları çalıştırmadan önce `TOKEN` değişkenini ayarlayın:

```bash
TOKEN=$SOIPACK_API_TOKEN
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

4. (İsteğe bağlı) Raporu paketleyin:
   ```bash
   curl -X POST "$BASE_URL/v1/pack" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"reportId\":\"<rapor-id>\"}"
   ```

   Manifest ve imza dosyaları oluşturulduktan sonra teslimattan önce doğrulamak için üretim anahtarınızla aşağıdaki komutu çalıştırabilirsiniz:

   ```bash
   node packages/cli/dist/index.js verify \
     --manifest data/packages/<paket-id>/manifest.json \
     --signature data/packages/<paket-id>/manifest.sig \
     --public-key path/to/ed25519_public.pem
   ```

## 4. Güncelleme ve Bakım

- Yeni bir sürüm yayınlandığında, hazırlık makinesinde `docker build` ve `docker save` adımlarını tekrar ederek yeni imajı içe aktarın.
- Kalıcı `data/` klasörünü düzenli olarak yedekleyin.
- `docker compose logs -f server` komutu ile hata ayıklama günlüklerini takip edebilirsiniz.

Bu adımlar tamamlandığında air-gapped ortamda `docker compose up -d` komutuyla SOIPack API'si PDF/rapor üretecek şekilde hazır olacaktır.
