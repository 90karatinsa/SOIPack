import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';

import { importReqIF } from './reqif';

const baseReqifXml = `<?xml version="1.0" encoding="UTF-8"?>
<REQ-IF>
  <CORE-CONTENT>
    <REQ-IF-CONTENT>
      <SPEC-OBJECTS>
        <SPEC-OBJECT IDENTIFIER="REQ-1">
          <LONG-NAME>Sample</LONG-NAME>
          <VALUES>
            <ATTRIBUTE-VALUE-STRING>
              <THE-VALUE>Example requirement</THE-VALUE>
            </ATTRIBUTE-VALUE-STRING>
          </VALUES>
        </SPEC-OBJECT>
      </SPEC-OBJECTS>
    </REQ-IF-CONTENT>
  </CORE-CONTENT>
</REQ-IF>`;

const zippedReqifBase64 =
  'UEsDBBQAAAAIAJqEOVt+Hqu+0wAAAMYBAAAMABwAc2FtcGxlLnJlcWlmVVQJAAOjb9Voo2/VaHV4CwABBAAAAAAEAAAAAIWQwXKCMBRF93xFJvsY3bl4hEH60DgaWhLcO22mw4ygou34+QZahNRFlznv5OblQnSrDuTbNpfyWId0NplSYuv340dZf4a0MCmb00gEkOMbk6kICIEky5ElmTKoTAsc+pn60GH9ignLFmtMjO6hj4l8cRdkKjEPaZsyo4Po1E2mlkzFWxR6X50OFvhAxt4u3hSox8jB2JhcLgqDrBsz7Y5q6UtOM6tfQeCte4Q09vxVNray9RX4MPbT+f/xwP/uBXz0+UdP/Lko4M+dAver7x0R3AFQSwECHgMUAAAACACahDlbfh6rvtMAAADGAQAADAAYAAAAAAABAAAApIEAAAAAc2FtcGxlLnJlcWlmVVQFAA Ojb9VodXgLAAEEAAAAAAQAAAAAUEsFBgAAAAABAAEAUgAAABkBAAAAAA=='.replace(/\s+/gu, '');

describe('importReqIF', () => {
  it('parses both .reqif and .reqifz inputs identically', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'reqif-import-'));
    const xmlPath = path.join(tempDir, 'example.reqif');
    const zipPath = path.join(tempDir, 'example.reqifz');

    await fs.writeFile(xmlPath, baseReqifXml, 'utf8');
    await fs.writeFile(zipPath, Buffer.from(zippedReqifBase64, 'base64'));

    const xmlResult = await importReqIF(xmlPath);
    const zipResult = await importReqIF(zipPath);

    await fs.rm(tempDir, { recursive: true, force: true });

    expect(xmlResult.warnings).toEqual(zipResult.warnings);
    expect(xmlResult.data).toEqual(zipResult.data);
    expect(xmlResult.data).toHaveLength(1);
    expect(xmlResult.data[0].title).toBe('Sample');
    expect(xmlResult.data[0].text).toContain('Example requirement');
  });
});
