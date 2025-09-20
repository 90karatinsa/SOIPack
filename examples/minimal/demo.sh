#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEMO_DIR="$ROOT_DIR/examples/minimal"
CONFIG="$DEMO_DIR/soipack.config.yaml"
CLI_DIST="$ROOT_DIR/packages/cli/dist/index.js"
LICENSE_PATH="$ROOT_DIR/data/licenses/demo-license.key"
WORK_DIR="$DEMO_DIR/.soipack"
DIST_DIR="$DEMO_DIR/dist"
RELEASE_DIR="$DEMO_DIR/release"
REPORT_DIR="$DIST_DIR/reports"
EXPECTED_DIR="$DEMO_DIR/EXPECTED"

echo "Cleaning previous demo artifacts..."
rm -rf "$WORK_DIR" "$DIST_DIR" "$RELEASE_DIR"

if [ ! -f "$LICENSE_PATH" ]; then
  echo "Demo lisans dosyası bulunamadı: $LICENSE_PATH" >&2
  exit 1
fi

if [ ! -f "$CLI_DIST" ]; then
  echo "Building SOIPack CLI..."
  npm run --workspace @soipack/cli build >/dev/null
fi

echo "Running pipeline with $CONFIG"
SOIPACK_DEMO_TIMESTAMP="2024-03-01T10:00:00.000Z" \
  node "$CLI_DIST" --license "$LICENSE_PATH" run --config "$CONFIG" || status=$?

if [ "${status:-0}" -ne 0 ] && [ "${status:-0}" -ne 2 ]; then
  exit "${status:-1}"
fi

echo "Preparing friendly report filenames..."
cp "$REPORT_DIR/compliance.html" "$REPORT_DIR/compliance_matrix.html"
cp "$REPORT_DIR/compliance.json" "$REPORT_DIR/compliance_matrix.json"
cp "$REPORT_DIR/trace.html" "$REPORT_DIR/trace_matrix.html"

echo "Rendering lightweight PDF summary..."
REPORT_DIR="$REPORT_DIR" python - <<'PY'
from pathlib import Path
import json
import os

def pdf_escape(text: str) -> str:
    return text.replace('\\', r'\\').replace('(', r'\(').replace(')', r'\)')

def create_pdf(path: Path, title: str, subtitle: str) -> None:
    lines = [
        "BT",
        "/F1 18 Tf",
        "72 760 Td",
        f"({pdf_escape(title)}) Tj",
        "0 -28 Td",
        "/F1 12 Tf",
        f"({pdf_escape(subtitle)}) Tj",
        "ET",
    ]
    stream_content = "\n".join(lines) + "\n"
    stream_bytes = stream_content.encode('utf-8')
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(stream_bytes)} >>\nstream\n{stream_content}endstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    parts: list[bytes] = [b"%PDF-1.4\n"]
    offsets: list[int] = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(sum(len(part) for part in parts))
        parts.append(f"{index} 0 obj\n{obj}\nendobj\n".encode('utf-8'))
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
    ).encode('utf-8')
    parts.append(trailer)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('wb') as handle:
        for part in parts:
            handle.write(part)

report_dir = Path(os.environ["REPORT_DIR"])
analysis = json.loads((report_dir / "analysis.json").read_text("utf-8"))
tests = analysis.get("tests", [])
passed = sum(1 for item in tests if item.get("status") == "passed")
failed = sum(1 for item in tests if item.get("status") == "failed")
skipped = sum(1 for item in tests if item.get("status") == "skipped")
requirements = analysis.get("requirements", [])
coverage = analysis.get("coverage", {}).get("totals", {}).get("statements", {})
percentage = coverage.get("percentage")
coverage_text = f"{coverage.get('covered', 0)}/{coverage.get('total', 0)} statements" if coverage else "No coverage data"
if percentage is not None:
    coverage_text += f" ({percentage}% coverage)"

project = analysis.get("metadata", {}).get("project", {})
project_name = project.get("name", "SOIPack Demo")
subtitle = (
    f"{len(requirements)} requirements · {len(tests)} tests "
    f"(\u2713 {passed} / \u2717 {failed} / \u25cb {skipped}) · {coverage_text}"
)
create_pdf(report_dir / "compliance_matrix.pdf", f"{project_name} Compliance", subtitle)
PY

if [ -d "$EXPECTED_DIR" ]; then
  echo "Syncing reference assets"
  cp "$REPORT_DIR/compliance_matrix.html" "$EXPECTED_DIR/compliance_matrix.html"
  cp "$REPORT_DIR/compliance_matrix.json" "$EXPECTED_DIR/compliance_matrix.json"
  cp "$REPORT_DIR/compliance_matrix.pdf" "$EXPECTED_DIR/compliance_matrix.pdf"
  cp "$REPORT_DIR/trace_matrix.html" "$EXPECTED_DIR/trace_matrix.html"
  cp "$REPORT_DIR/gaps.html" "$EXPECTED_DIR/gaps.html"
  cp "$RELEASE_DIR/manifest.json" "$EXPECTED_DIR/manifest.json"
  cp "$RELEASE_DIR/manifest.sig" "$EXPECTED_DIR/manifest.sig"
fi

echo "Demo artifacts prepared under $DIST_DIR and $RELEASE_DIR"
