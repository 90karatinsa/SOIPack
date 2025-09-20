export const parseCsv = (content: string): string[][] => {
  const rows: string[][] = [];
  let current = '';
  let row: string[] = [];
  let inQuotes = false;

  const pushValue = () => {
    row.push(current);
    current = '';
  };

  const pushRow = () => {
    if (inQuotes) {
      current += '\n';
      return;
    }
    pushValue();
    rows.push(row);
    row = [];
  };

  for (let i = 0; i < content.length; i += 1) {
    const char = content[i];

    if (char === '"') {
      if (inQuotes && content[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === ',' && !inQuotes) {
      pushValue();
      continue;
    }

    if (char === '\r') {
      if (content[i + 1] === '\n') {
        continue;
      }
    }

    if (char === '\n' && !inQuotes) {
      pushRow();
      continue;
    }

    current += char;
  }

  if (current.length > 0 || row.length > 0) {
    pushValue();
    rows.push(row);
  }

  return rows;
};
