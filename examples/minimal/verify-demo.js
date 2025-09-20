#!/usr/bin/env node
const { execFileSync } = require('child_process');
const { createHash } = require('crypto');
const fs = require('fs');
const path = require('path');

const assert = (condition, message) => {
  if (!condition) {
    throw new Error(message);
  }
};

const demoDir = path.resolve(__dirname);
const reportDir = path.join(demoDir, 'dist', 'reports');
const releaseDir = path.join(demoDir, 'release');

const runDemo = () => {
  execFileSync(path.join(demoDir, 'demo.sh'), { stdio: 'inherit' });
};

const ensureFile = (filePath) => {
  assert(fs.existsSync(filePath), `Beklenen dosya bulunamadı: ${filePath}`);
  const stats = fs.statSync(filePath);
  assert(stats.isFile(), `Dosya bekleniyordu: ${filePath}`);
  assert(stats.size > 0, `Dosya boş: ${filePath}`);
};

const verifyHtml = (filePath) => {
  const content = fs.readFileSync(filePath, 'utf8');
  assert(content.includes('SOIPack Demo Avionics Uyum Matrisi'), 'Uyum matrisi başlığı eksik.');
  assert(/Rapor Tarihi:\s+2024-03-01 10:00 UTC/.test(content), 'Sabitlenen zaman damgası bulunamadı.');
  assert(content.includes('Eksik Kanıtlar'), 'Eksik kanıt tablosu bulunamadı.');
};

const verifyComplianceJson = (filePath) => {
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  assert(data.stats?.tests?.total === 12, 'Toplam test sayısı beklenenden farklı.');
  assert(data.stats?.tests?.failed === 2, 'Başarısız test sayısı beklenenden farklı.');
  assert(data.stats?.requirements?.total >= 10, 'Gereksinim sayısı beklenenden az.');
  const generated = data.generatedAt;
  assert(generated === '2024-03-01T10:00:00.000Z', 'Zaman damgası beklenen değerle eşleşmiyor.');
};

const verifyManifest = () => {
  const manifestPath = path.join(releaseDir, 'manifest.json');
  const signaturePath = path.join(releaseDir, 'manifest.sig');
  ensureFile(manifestPath);
  ensureFile(signaturePath);
  const manifestContent = fs.readFileSync(manifestPath, 'utf8');
  const expectedHash = createHash('sha256').update(manifestContent).digest('hex');
  const signature = fs.readFileSync(signaturePath, 'utf8').trim();
  assert(signature === expectedHash, 'Manifest imzası beklenen hash değeriyle uyuşmuyor.');
};

const verifyZip = () => {
  const entries = fs.readdirSync(releaseDir);
  const zipName = entries.find((name) => name.startsWith('soi-pack-') && name.endsWith('.zip'));
  assert(zipName, 'soi-pack- ile başlayan zip dosyası bulunamadı.');
};

const main = () => {
  runDemo();

  const complianceHtml = path.join(reportDir, 'compliance_matrix.html');
  const complianceJson = path.join(reportDir, 'compliance_matrix.json');
  const compliancePdf = path.join(reportDir, 'compliance_matrix.pdf');
  const traceHtml = path.join(reportDir, 'trace_matrix.html');
  const gapsHtml = path.join(reportDir, 'gaps.html');

  [complianceHtml, complianceJson, compliancePdf, traceHtml, gapsHtml].forEach(ensureFile);

  verifyHtml(complianceHtml);
  verifyComplianceJson(complianceJson);
  verifyManifest();
  verifyZip();

  const traceContent = fs.readFileSync(traceHtml, 'utf8');
  assert(traceContent.includes('REQ-1'), 'İzlenebilirlik matrisi REQ-1 bilgisini içermiyor.');
  assert(traceContent.includes('REQ-7'), 'İzlenebilirlik matrisi REQ-7 bilgisini içermiyor.');

  console.log('Demo çıktıları başarıyla doğrulandı.');
};

main();
