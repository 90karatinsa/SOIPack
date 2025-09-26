# Workspaces API

## GET /v1/workspaces/{workspaceId}/documents/{documentId}

Belirli bir çalışma alanı belgesinin son revizyonunu, sayfalı yorumlarını ve imza geçmişini döndürür. İstek, JWT token'ı ve geçerli bir SOIPack lisans anahtarını gerektirir.

### Gerekli Başlıklar
- `Authorization: Bearer <token>`
- `X-SOIPACK-License: <base64>`

### Path Parametreleri
- `workspaceId` – Belgenin ait olduğu çalışma alanı kimliği.
- `documentId` – Erişilecek belge kimliği.

### Sorgu Parametreleri
- `cursor` *(opsiyonel)* – Yorumları sayfalamak için bir önceki yanıttan alınan imleç değeri.
- `limit` *(opsiyonel)* – Döndürülecek maksimum yorum sayısı (1-100 arası, varsayılan 20).

### Örnek İstek
```http
GET /v1/workspaces/avionics/documents/requirements?limit=10 HTTP/1.1
Authorization: Bearer eyJhbGciOi...
X-SOIPACK-License: ZXhhbXBsZS1saWNlbnNl
```

### Yanıt Gövdesi
```json
{
  "document": {
    "id": "requirements",
    "tenantId": "tenant-1",
    "workspaceId": "avionics",
    "kind": "requirements",
    "title": "Flight Controls",
    "createdAt": "2024-03-01T09:00:00.000Z",
    "updatedAt": "2024-03-05T18:42:10.000Z",
    "revision": {
      "id": "rev-3",
      "number": 3,
      "hash": "5b2d0ce5f7a9a1d4",
      "authorId": "alice",
      "createdAt": "2024-03-05T18:42:10.000Z",
      "content": [
        {
          "id": "REQ-001",
          "title": "The aircraft shall enter fail-safe mode on sensor disagreement.",
          "description": "Primary and secondary sensor suites must be continuously cross-checked.",
          "status": "draft",
          "tags": ["safety", "level-a"]
        }
      ]
    }
  },
  "comments": [
    {
      "id": "c1",
      "documentId": "requirements",
      "revisionId": "rev-3",
      "tenantId": "tenant-1",
      "workspaceId": "avionics",
      "authorId": "qa-lead",
      "body": "Lütfen sensör doğrulama testi için referans ekleyin.",
      "createdAt": "2024-03-05T19:10:00.000Z"
    }
  ],
  "signoffs": [
    {
      "id": "s1",
      "documentId": "requirements",
      "revisionId": "rev-2",
      "tenantId": "tenant-1",
      "workspaceId": "avionics",
      "revisionHash": "1f0c9bd4a1f5d6b2",
      "status": "pending",
      "requestedBy": "alice",
      "requestedFor": "der",
      "createdAt": "2024-03-02T14:00:00.000Z",
      "updatedAt": "2024-03-02T14:00:00.000Z",
      "approvedAt": null,
      "rejectedAt": null
    }
  ],
  "nextCursor": null
}
```

### Yanıt Alanları
- `document` – Belgenin meta verileri ve son revizyonu.
  - `revision.hash` – Son revizyonun normalleştirilmiş (küçük harf) karması.
  - `revision.content` – Gereksinim kayıtlarının listesi (ID, başlık, açıklama, durum, etiketler).
- `comments` – Artan kronolojik sırada yorumlar.
- `signoffs` – İlk imza isteğinden itibaren sıralanmış imza kayıtları. `status` alanı `pending` veya `approved` değerini alır.
- `nextCursor` – Daha fazla yorum olduğunda kullanılacak imleç; aksi halde `null`.

### Hata Kodları
- `400 INVALID_REQUEST` – Geçersiz sayfalama parametreleri.
- `403 INSUFFICIENT_SCOPE` – Kullanıcı gerekli rol veya scope'a sahip değil.
- `404 WORKSPACE_DOCUMENT_NOT_FOUND` – Belge mevcut değil ya da kiracıyla eşleşmiyor.

## GET /v1/manifests/{manifestId}/proofs

Belirli bir paket manifestindeki tüm dosyalar için üretilen Merkle kanıtlarını listeler. Yanıt, manifestin Merkle özetini (`merkle.root`) ve her dosya için `proof` (kanıtın serileştirilmiş JSON dizgesi) ile `verified` bayrağını döndürür. İstek yalnızca `reader`, `maintainer` veya `admin` rolleri tarafından yapılabilir.

### Yanıt Gövdesi
```json
{
  "manifestId": "abcd1234ef56",
  "jobId": "2f8d6c3b4a1e5d79",
  "merkle": {
    "algorithm": "ledger-merkle-v1",
    "root": "9d4a...",
    "manifestDigest": "73f1...",
    "snapshotId": "manifest:73f1..."
  },
  "files": [
    {
      "path": "reports/summary.txt",
      "sha256": "2b6d...",
      "verified": true,
      "proof": {
        "algorithm": "ledger-merkle-v1",
        "merkleRoot": "9d4a...",
        "proof": "{\"leaf\":{...}}"
      }
    }
  ]
}
```

## GET /v1/manifests/{manifestId}/proofs/{filePath}

Tek bir manifest dosyasına ait kanıtı döner. `filePath` parametresi URL içinde kodlanmış olmalıdır (ör. `reports%2Fsummary.txt`). Sunucu, kanıtı doğrular ve `verified: true` olarak işaretler; doğrulama başarısız olursa `500 PROOF_INVALID` hatası döner.

### Hata Kodları
- `400 INVALID_REQUEST` – `manifestId` veya `filePath` parametresi eksik/geçersiz.
- `403 INSUFFICIENT_SCOPE` – Kullanıcı gerekli role sahip değil.
- `404 MANIFEST_FILE_NOT_FOUND` – Dosya manifestte bulunamadı.
- `500 PROOF_INVALID` – Kanıt doğrulaması sırasında hata oluştu.
