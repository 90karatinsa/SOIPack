import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';

import { parseReqifStream } from './reqif';

describe('parseReqifStream', () => {
  it('extracts html content, hierarchy and trace links from ReqIF documents', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'reqif-parser-'));
    const filePath = path.join(tempDir, 'sample.reqif');
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<REQ-IF>
  <CORE-CONTENT>
    <REQ-IF-CONTENT>
      <SPEC-OBJECTS>
        <SPEC-OBJECT IDENTIFIER="REQ-1">
          <LONG-NAME>Autopilot engages</LONG-NAME>
          <SHORT-NAME>AP-ENGAGE</SHORT-NAME>
          <VALUES>
            <ATTRIBUTE-VALUE-XHTML>
              <THE-VALUE>
                <div>
                  <p>The autopilot <em>shall</em> engage.</p>
                  <ul><li>First</li><li>Second</li></ul>
                </div>
              </THE-VALUE>
            </ATTRIBUTE-VALUE-XHTML>
          </VALUES>
        </SPEC-OBJECT>
        <SPEC-OBJECT IDENTIFIER="REQ-2">
          <LONG-NAME>Mode selection</LONG-NAME>
          <VALUES>
            <ATTRIBUTE-VALUE-XHTML>
              <THE-VALUE>
                <div>Supports <strong>manual</strong> and automatic.</div>
                <ATTRIBUTE-VALUE-XHTML>
                  <THE-VALUE><p>Nested <span>ignored</span> value</p></THE-VALUE>
                </ATTRIBUTE-VALUE-XHTML>
              </THE-VALUE>
            </ATTRIBUTE-VALUE-XHTML>
            <ATTRIBUTE-VALUE-STRING>
              <THE-VALUE>Fallback string description</THE-VALUE>
            </ATTRIBUTE-VALUE-STRING>
          </VALUES>
        </SPEC-OBJECT>
      </SPEC-OBJECTS>
      <SPECIFICATIONS>
        <SPECIFICATION>
          <HIERARCHY>
            <SPEC-HIERARCHY>
              <SPEC-OBJECT-REF>REQ-1</SPEC-OBJECT-REF>
              <CHILDREN>
                <SPEC-HIERARCHY>
                  <SPEC-OBJECT-REF>REQ-2</SPEC-OBJECT-REF>
                </SPEC-HIERARCHY>
              </CHILDREN>
            </SPEC-HIERARCHY>
          </HIERARCHY>
        </SPECIFICATION>
      </SPECIFICATIONS>
      <SPEC-RELATIONS>
        <SPEC-RELATION>
          <SOURCE><SPEC-OBJECT-REF>REQ-2</SPEC-OBJECT-REF></SOURCE>
          <TARGET><SPEC-OBJECT-REF>REQ-1</SPEC-OBJECT-REF></TARGET>
        </SPEC-RELATION>
      </SPEC-RELATIONS>
    </REQ-IF-CONTENT>
  </CORE-CONTENT>
</REQ-IF>`;

    await fs.writeFile(filePath, xml, 'utf8');

    const result = await parseReqifStream(filePath);

    await fs.rm(tempDir, { recursive: true, force: true });

    expect(result.warnings).toHaveLength(0);
    expect(result.data).toHaveLength(2);

    const first = result.data.find((item) => item.id === 'REQ-1');
    const second = result.data.find((item) => item.id === 'REQ-2');

    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(first?.title).toBe('Autopilot engages');
    expect(first?.shortName).toBe('AP-ENGAGE');
    expect(first?.childrenIds).toEqual(['REQ-2']);
    expect(first?.descriptionHtml).toContain('<div>');

    expect(second?.parentId).toBe('REQ-1');
    expect(second?.tracesTo).toEqual(['REQ-1']);
    expect(second?.descriptionHtml).toContain('<div>Supports <strong>manual</strong> and automatic.</div>');
    expect(second?.text).toContain('Supports manual and automatic.');
    expect(second?.text).toContain('Fallback string description');
  });
});
