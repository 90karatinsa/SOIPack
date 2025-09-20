#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT_DIR/examples/minimal"
TARGET_DIR="$ROOT_DIR/.demo"
CONFIG_PATH="$TARGET_DIR/soipack.config.yaml"
LICENSE_PATH="$ROOT_DIR/data/licenses/demo-license.key"
CLI_DIST="$ROOT_DIR/packages/cli/dist/index.js"
SOIPACK_BIN="$ROOT_DIR/node_modules/.bin/soipack"
RELEASE_DIR="$TARGET_DIR/release"
REPORT_DIR="$TARGET_DIR/dist/reports"

if [ ! -f "$LICENSE_PATH" ]; then
  echo "Demo lisans dosyası bulunamadı: $LICENSE_PATH" >&2
  echo "Lütfen data/licenses/demo-license.key dosyasının mevcut olduğundan emin olun." >&2
  exit 1
fi

echo "📦 Demo çalışma alanı hazırlanıyor: $TARGET_DIR"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"
cp -R "$SRC_DIR"/. "$TARGET_DIR"/
rm -rf "$TARGET_DIR/.soipack" "$TARGET_DIR/dist" "$TARGET_DIR/release"

if [ -f "$CONFIG_PATH" ]; then
  perl -0pi -e 's|git: "../.."|git: ".."|' "$CONFIG_PATH"
  perl -0pi -e 's|file: "../../data/|file: "../data/|' "$CONFIG_PATH"
fi

if [ ! -d "$ROOT_DIR/node_modules" ] || [ ! -d "$ROOT_DIR/node_modules/.bin" ]; then
  echo "📥 Bağımlılıklar yükleniyor..."
  (cd "$ROOT_DIR" && npm install >/dev/null)
fi

if [ ! -f "$SOIPACK_BIN" ] || [ ! -f "$CLI_DIST" ]; then
  echo "🛠️  SOIPack CLI derleniyor..."
  (cd "$ROOT_DIR" && npm run --workspace @soipack/cli build >/dev/null)
fi

SOIPACK_CMD=("$SOIPACK_BIN")
if [ ! -x "$SOIPACK_BIN" ]; then
  SOIPACK_CMD=("node" "$CLI_DIST")
fi

echo "▶️  soipack run çalıştırılıyor..."
set +e
SOIPACK_DEMO_TIMESTAMP="2024-03-01T10:00:00.000Z" \
  "${SOIPACK_CMD[@]}" --license "$LICENSE_PATH" run --config "$CONFIG_PATH"
status=$?
set -e

if [ "$status" -ne 0 ] && [ "$status" -ne 2 ]; then
  echo "❌ soipack run $status kodu ile sonlandı" >&2
  exit "$status"
fi

if [ ! -d "$REPORT_DIR" ]; then
  echo "❌ Rapor dizini bulunamadı: $REPORT_DIR" >&2
  exit 1
fi

mkdir -p "$REPORT_DIR"
if [ -f "$REPORT_DIR/compliance.html" ]; then
  cp "$REPORT_DIR/compliance.html" "$REPORT_DIR/compliance_matrix.html"
fi
if [ -f "$REPORT_DIR/compliance.json" ]; then
  cp "$REPORT_DIR/compliance.json" "$REPORT_DIR/compliance_matrix.json"
fi
if [ -f "$REPORT_DIR/trace.html" ]; then
  cp "$REPORT_DIR/trace.html" "$REPORT_DIR/trace_matrix.html"
fi

python - "$REPORT_DIR" <<'PY'
import json
import sys
from pathlib import Path

report_dir = Path(sys.argv[1])
analysis_path = report_dir / "analysis.json"
output_path = report_dir / "compliance_matrix.pdf"
if not analysis_path.exists():
    sys.exit(0)
analysis = json.loads(analysis_path.read_text("utf-8"))
project = analysis.get("metadata", {}).get("project", {})
requirements = analysis.get("requirements", [])
tests = analysis.get("tests", [])
coverage = analysis.get("coverage", {}).get("totals", {}).get("statements", {})
passed = sum(1 for item in tests if item.get("status") == "passed")
failed = sum(1 for item in tests if item.get("status") == "failed")
skipped = sum(1 for item in tests if item.get("status") == "skipped")
covered = coverage.get("covered", 0)
total = coverage.get("total", 0)
percentage = coverage.get("percentage")
subtitle_parts = [
    f"{len(requirements)} requirements",
    f"{len(tests)} tests (✓ {passed} / ✗ {failed} / ○ {skipped})",
    f"{covered}/{total} statements"
]
if percentage is not None:
    subtitle_parts[-1] += f" ({percentage}% coverage)"
project_name = project.get("name", "SOIPack Demo")
subtitle = " · ".join(subtitle_parts)

def escape(text: str) -> str:
    return text.replace("\\", r"\\\\").replace("(", r"\\(").replace(")", r"\\)")

lines = [
    "BT",
    "/F1 18 Tf",
    "72 760 Td",
    f"({escape(project_name)} Compliance Summary) Tj",
    "0 -28 Td",
    "/F1 12 Tf",
    f"({escape(subtitle)}) Tj",
    "ET",
]
content = "\n".join(lines) + "\n"
stream = content.encode("utf-8")
objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    f"<< /Length {len(stream)} >>\nstream\n{content}endstream",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
]
parts = [b"%PDF-1.4\n"]
offsets = []
for index, obj in enumerate(objects, start=1):
    offsets.append(sum(len(part) for part in parts))
    parts.append(f"{index} 0 obj\n{obj}\nendobj\n".encode("utf-8"))
xref_offset = sum(len(part) for part in parts)
entries = ["0000000000 65535 f \n"]
entries.extend(f"{offset:010d} 00000 n \n" for offset in offsets)
trailer = (
    "xref\n"
    f"0 {len(objects) + 1}\n"
    + "".join(entries)
    + "trailer\n"
    + f"<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
    + "startxref\n"
    + f"{xref_offset}\n"
    + "%%EOF\n"
).encode("utf-8")
parts.append(trailer)
output_path.parent.mkdir(parents=True, exist_ok=True)
with output_path.open("wb") as handle:
    for part in parts:
        handle.write(part)
PY

ZIP_PATH=$(find "$RELEASE_DIR" -maxdepth 1 -type f -name 'soi-pack-*.zip' -print -quit)
if [ -z "$ZIP_PATH" ]; then
  echo "❌ Paket bulunamadı: $RELEASE_DIR altında soi-pack-*.zip yok" >&2
  exit 1
fi

echo "\n✅ Demo başarıyla tamamlandı"
echo "  Paket: $ZIP_PATH"
for report in \
  "$REPORT_DIR/compliance_matrix.html" \
  "$REPORT_DIR/compliance_matrix.json" \
  "$REPORT_DIR/compliance_matrix.pdf" \
  "$REPORT_DIR/trace_matrix.html" \
  "$REPORT_DIR/gaps.html"; do
  if [ -f "$report" ]; then
    echo "  Rapor: $report"
  fi
done

echo "\n👉 Çıktılar $TARGET_DIR içinde hazır."
