/**
 * Converts IPv4 address to IPv6 format.
 * Format: 10.AA.BB.CCC → {prefix}AABB::CCC
 *
 * @param {string} ipv4 The IPv4 address to convert
 * @param {string} prefix The IPv6 prefix (e.g., "2404:e80:a137:")
 * @return {string} The converted IPv6 address
 * @customfunction
 */
function IPv4toIPv6(ipv4, prefix) {
  if (!ipv4 || ipv4 === '') return '';
  if (!prefix) {
    throw new Error('Prefix is required (e.g., "2404:e80:a137:")');
  }

  // Handle if input is a range (single cell)
  if (Array.isArray(ipv4)) {
    return ipv4.map(row => row.map(cell => IPv4toIPv6(cell, prefix)));
  }

  const str = String(ipv4).trim();
  const prefixStr = String(prefix).trim();

  // Ensure prefix ends with exactly one colon
  const normalizedPrefix = prefixStr.replace(/:+$/, '') + ':';

  // Parse IPv4: 10.AA.BB.CCC
  const match = str.match(/^10\.([^.]+)\.([^.]+)\.([^.]+)$/i);
  if (!match) {
    throw new Error('Invalid format: must be 10.AA.BB.CCC');
  }

  let [, aa, bb, ccc] = match;

  // Process AA
  let aaOut;
  if (aa.toUpperCase() === 'X') {
    throw new Error('AA cannot be X');
  } else if (/^[A-Za-z]+$/.test(aa)) {
    aaOut = aa;
  } else {
    const aaNum = parseInt(aa, 10);
    if (isNaN(aaNum) || aaNum > 99) {
      throw new Error('AA must be 0-99');
    }
    aaOut = String(aaNum);
  }

  // Process BB
  let bbOut;
  if (bb.toUpperCase() === 'X') {
    bbOut = '00';
  } else if (/^[A-Za-z]+$/.test(bb)) {
    bbOut = bb;
  } else {
    const bbNum = parseInt(bb, 10);
    if (isNaN(bbNum) || bbNum > 99) {
      throw new Error('BB must be 0-99 or X');
    }
    bbOut = String(bbNum).padStart(2, '0');
  }

  // Process CCC
  let cccOut;
  if (ccc.toUpperCase() === 'X') {
    cccOut = '';
  } else if (/^[A-Za-z]+$/.test(ccc)) {
    cccOut = ccc;
  } else {
    const cccNum = parseInt(ccc, 10);
    if (isNaN(cccNum) || cccNum > 256) {
      throw new Error('CCC must be 0-256 or X');
    }
    cccOut = String(cccNum);
  }

  return normalizedPrefix + aaOut + bbOut + '::' + cccOut;
}

/**
 * Converts IPv4 to IPv6 with formatting preservation.
 * Automatically finds columns by header names and gets prefix from above header.
 */
function convertWithFormatting() {
  const sheet = SpreadsheetApp.getActiveSheet();
  const ui = SpreadsheetApp.getUi();

  // Find headers and columns
  const config = findColumnsAndPrefix(sheet);

  if (!config) {
    ui.alert('Error', 'Could not find IPv4 and/or IPv6 columns.\n\n' +
      'Looking for headers matching "IPv4.*" and "IPv6.*"', ui.ButtonSet.OK);
    return;
  }

  const { ipv4Col, ipv6Col, ipv6CidrCol, headerRow, prefix } = config;

  if (!prefix) {
    ui.alert('Error', 'Could not find IPv6 prefix.\n\n' +
      'The prefix should be in the cell above the IPv6 header.', ui.ButtonSet.OK);
    return;
  }

  // Confirm with user
  const response = ui.alert(
    'Convert IPv4 to IPv6',
    `Found configuration:\n` +
    `• IPv4 column: ${columnToLetter(ipv4Col)}\n` +
    `• IPv6 column: ${columnToLetter(ipv6Col)}\n` +
    `• IPv6 CIDR column: ${ipv6CidrCol ? columnToLetter(ipv6CidrCol) : '(not found, using /128)'}\n` +
    `• Header row: ${headerRow}\n` +
    `• Prefix: ${prefix}\n\n` +
    `Proceed with conversion?`,
    ui.ButtonSet.OK_CANCEL
  );

  if (response !== ui.Button.OK) return;

  // Get data range (from header row + 1 to last row with data)
  const lastRow = sheet.getLastRow();
  let processed = 0;
  let skipped = 0;
  let errors = [];

  for (let row = headerRow + 1; row <= lastRow; row++) {
    const sourceCell = sheet.getRange(row, ipv4Col);
    const targetCell = sheet.getRange(row, ipv6Col);

    // Get CIDR value (default to /128 if not found or empty)
    let cidr = 128;
    if (ipv6CidrCol) {
      const cidrValue = String(sheet.getRange(row, ipv6CidrCol).getValue()).trim();
      const cidrMatch = cidrValue.match(/\/(\d+)/);
      if (cidrMatch) {
        cidr = parseInt(cidrMatch[1], 10);
      }
    }

    try {
      if (convertCellWithFormatting(sourceCell, targetCell, prefix, cidr)) {
        processed++;
      } else {
        skipped++;
      }
    } catch (e) {
      errors.push(`Row ${row}: ${e.message}`);
    }
  }

  let message = `Converted ${processed} cell(s), skipped ${skipped}.`;
  if (errors.length > 0) {
    message += `\n\nErrors:\n${errors.slice(0, 5).join('\n')}`;
    if (errors.length > 5) message += `\n... and ${errors.length - 5} more`;
  }
  ui.alert('Conversion Complete', message, ui.ButtonSet.OK);
}

/**
 * Find IPv4 column, IPv6 column (leftmost), IPv6 CIDR column, header row, and prefix.
 * Handles multi-row headers by scanning first 10 rows.
 */
function findColumnsAndPrefix(sheet) {
  const maxHeaderRows = 10;
  const lastCol = sheet.getLastColumn();

  let ipv4Col = null;
  let ipv6Col = null;
  let ipv6CidrCol = null;
  let headerRow = null;

  // Scan first rows for headers
  for (let row = 1; row <= maxHeaderRows; row++) {
    const rowValues = sheet.getRange(row, 1, 1, lastCol).getValues()[0];

    for (let col = 0; col < rowValues.length; col++) {
      const cellValue = String(rowValues[col]).trim();

      // Check for IPv4 header
      if (!ipv4Col && /^IPv4/i.test(cellValue)) {
        ipv4Col = col + 1; // Convert to 1-based
        if (!headerRow) headerRow = row;
      }

      // Check for IPv6 header (take leftmost)
      if (!ipv6Col && /^IPv6/i.test(cellValue)) {
        ipv6Col = col + 1; // Convert to 1-based
        if (!headerRow) headerRow = row;
      }
    }

    // If we found both, stop scanning
    if (ipv4Col && ipv6Col) break;
  }

  if (!ipv4Col || !ipv6Col || !headerRow) {
    return null;
  }

  // Find CIDR column - look for "CIDR" header after the IPv6 column
  const headerValues = sheet.getRange(headerRow, 1, 1, lastCol).getValues()[0];
  for (let col = ipv6Col; col < headerValues.length; col++) {
    const cellValue = String(headerValues[col]).trim();
    if (/^CIDR$/i.test(cellValue)) {
      ipv6CidrCol = col + 1; // Convert to 1-based
      break;
    }
  }

  // Get prefix from cell above IPv6 header
  let prefix = null;
  if (headerRow > 1) {
    const prefixCell = sheet.getRange(headerRow - 1, ipv6Col);
    prefix = String(prefixCell.getValue()).trim();

    // Normalize prefix - ensure exactly one trailing colon
    if (prefix) {
      prefix = prefix.replace(/:+$/, '') + ':';
    }
  }

  return { ipv4Col, ipv6Col, ipv6CidrCol, headerRow, prefix };
}

/**
 * Convert column number to letter (1 = A, 2 = B, etc.)
 */
function columnToLetter(col) {
  let letter = '';
  while (col > 0) {
    const mod = (col - 1) % 26;
    letter = String.fromCharCode(65 + mod) + letter;
    col = Math.floor((col - 1) / 26);
  }
  return letter;
}

/**
 * Converts a single IPv4 cell to IPv6 with formatting.
 * @param {Range} sourceCell - Source cell with IPv4 address
 * @param {Range} targetCell - Target cell for IPv6 address
 * @param {string} prefix - IPv6 prefix (e.g., "2404:e80:a137:")
 * @param {number} cidr - IPv6 CIDR value (56, 64, or 128)
 */
function convertCellWithFormatting(sourceCell, targetCell, prefix, cidr) {
  const sourceRichText = sourceCell.getRichTextValue();
  if (!sourceRichText) return false;

  const sourceText = sourceRichText.getText().trim();
  if (!sourceText) return false;

  // Parse IPv4: 10.AA.BB.CCC
  const ipv4Match = sourceText.match(/^10\.([^.]+)\.([^.]+)\.([^.]+)$/);
  if (!ipv4Match) return false;

  const [, aaValue, bbValue, cccValue] = ipv4Match;

  const bbIsX = bbValue.toUpperCase() === 'X';
  const cccIsX = cccValue.toUpperCase() === 'X';

  // Determine what to do with CCC based on CIDR
  // /56 and /64: CCC should be dropped (only OK if X)
  // /128: CCC is kept (X stays as X)
  const shouldDropCCC = (cidr === 56 || cidr === 64);

  if (shouldDropCCC && !cccIsX) {
    // Would drop a non-X value - this is an error
    throw new Error(`CCC="${cccValue}" would be dropped for /${cidr} (only X allowed)`);
  }

  // Convert values
  let aaOut, bbOut, cccOut;

  // Process AA - never X
  if (aaValue.toUpperCase() === 'X') {
    throw new Error('AA cannot be X');
  } else if (/[A-Za-z]/.test(aaValue)) {
    // Contains letters - pass through as-is (template/placeholder)
    aaOut = aaValue;
  } else {
    const aaNum = parseInt(aaValue, 10);
    if (isNaN(aaNum) || aaNum > 99) {
      throw new Error('AA must be 0-99');
    }
    aaOut = String(aaNum);
  }

  // Process BB
  if (bbIsX) {
    // For /128, keep X as literal "X"; otherwise convert to "00"
    bbOut = (cidr === 128) ? 'X' : '00';
  } else if (/[A-Za-z]/.test(bbValue)) {
    // Contains letters - pass through as-is (template/placeholder)
    // Pad with leading zero if single char
    bbOut = bbValue.length === 1 ? '0' + bbValue : bbValue;
  } else {
    const bbNum = parseInt(bbValue, 10);
    if (isNaN(bbNum) || bbNum > 99) {
      throw new Error('BB must be 0-99 or X');
    }
    bbOut = String(bbNum).padStart(2, '0');
  }

  // Process CCC
  if (cccIsX) {
    // For /128, keep X as literal "X"; otherwise drop it (empty)
    cccOut = (cidr === 128) ? 'X' : '';
  } else if (/[A-Za-z]/.test(cccValue)) {
    // Contains letters (like "1X", "CCD") - pass through as-is
    cccOut = cccValue;
  } else {
    const cccNum = parseInt(cccValue, 10);
    if (isNaN(cccNum) || cccNum > 256) {
      throw new Error('CCC must be 0-256 or X');
    }
    cccOut = String(cccNum);
  }

  // Build output string
  const outputText = prefix + aaOut + bbOut + '::' + cccOut;
  const prefixLen = prefix.length;
  const aaOutLen = aaOut.length;
  const bbOutLen = bbOut.length;

  // Find dot positions in source to locate formatting
  const dotPositions = [];
  for (let i = 0; i < sourceText.length; i++) {
    if (sourceText[i] === '.') dotPositions.push(i);
  }

  if (dotPositions.length < 3) return false;

  const aaStart = dotPositions[0] + 1;
  const aaEnd = dotPositions[1];
  const bbStart = dotPositions[1] + 1;
  const bbEnd = dotPositions[2];
  const cccStart = dotPositions[2] + 1;
  const cccEnd = sourceText.length;

  // Build rich text for target
  const builder = SpreadsheetApp.newRichTextValue().setText(outputText);

  // Apply AA styles (character by character to preserve multi-color formatting)
  const aaOutStart = prefixLen;
  for (let i = 0; i < aaOutLen; i++) {
    // Map output position to source position (use last source char if output is longer)
    const srcOffset = Math.min(i, (aaEnd - aaStart) - 1);
    if (srcOffset >= 0) {
      const srcIdx = aaStart + srcOffset;
      const style = sourceRichText.getTextStyle(srcIdx, srcIdx + 1);
      if (style) {
        builder.setTextStyle(aaOutStart + i, aaOutStart + i + 1, style);
      }
    }
  }

  // Apply BB styles (character by character)
  // Special case: if source BB is single char (like X), apply its style to all output chars
  const bbOutStart = prefixLen + aaOutLen;
  const bbSrcLen = bbEnd - bbStart;
  for (let i = 0; i < bbOutLen; i++) {
    // If source is shorter than output (e.g., X -> 00), repeat the last source char's style
    const srcOffset = Math.min(i, bbSrcLen - 1);
    if (srcOffset >= 0) {
      const srcIdx = bbStart + srcOffset;
      const style = sourceRichText.getTextStyle(srcIdx, srcIdx + 1);
      if (style) {
        builder.setTextStyle(bbOutStart + i, bbOutStart + i + 1, style);
      }
    }
  }

  // Apply CCC styles (character by character, after ::)
  const cccOutStart = prefixLen + aaOutLen + bbOutLen + 2; // +2 for ::
  const cccSrcLen = cccEnd - cccStart;
  if (cccOut.length > 0) {
    for (let i = 0; i < cccOut.length; i++) {
      // If source is shorter than output, repeat the last source char's style
      const srcOffset = Math.min(i, cccSrcLen - 1);
      if (srcOffset >= 0) {
        const srcIdx = cccStart + srcOffset;
        const style = sourceRichText.getTextStyle(srcIdx, srcIdx + 1);
        if (style) {
          builder.setTextStyle(cccOutStart + i, cccOutStart + i + 1, style);
        }
      }
    }
  }

  targetCell.setRichTextValue(builder.build());
  return true;
}

/**
 * Creates menu when spreadsheet opens.
 */
function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu('IPv4/IPv6 Tools')
    .addItem('Convert IPv4 to IPv6 (with formatting)', 'convertWithFormatting')
    .addToUi();
}
