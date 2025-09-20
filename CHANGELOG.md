# Changelog

## [0.1.0] - 2025-09-20
### Added
- Offline lisans doğrulaması: `license.key` dosyası Ed25519 imzası ile doğrulanıyor ve geçersiz olduğunda CLI komutları durduruluyor.
- JSON formatında yapılandırılmış loglama pino ile sağlandı; `--verbose` bayrağı ayrıntılı log seviyesini etkinleştiriyor.
- `soipack --version` çıktısı SemVer sürümü ile birlikte aktif commit özetini gösteriyor.
- Telemetri varsayılan olarak kapalı tutularak gizlilik beklentisi korunuyor.
