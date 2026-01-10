#!/usr/bin/env python3
"""Deploy IPv4toIPv6 functions to Google Spreadsheet via Apps Script API."""

import json
import google.auth
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# The spreadsheet ID from the URL
SPREADSHEET_ID = "1fFm2irzmnLb7RQNmAi4DmAm2_c61wrd5A2j3ZzdqIWE"

# The Apps Script code to deploy (embedded as multi-line string)
APPS_SCRIPT_CODE = r'''
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

  // Ensure prefix ends with colon
  const normalizedPrefix = prefixStr.endsWith(':') ? prefixStr : prefixStr + ':';

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
 * Copies rich text formatting from IPv4 source cells to IPv6 formula cells.
 */
function copyIPv4Formatting() {
  const sheet = SpreadsheetApp.getActiveSheet();
  const selection = sheet.getActiveRange();

  const ui = SpreadsheetApp.getUi();
  const response = ui.alert(
    'Copy IPv4 Formatting',
    'This will copy formatting from IPv4 source cells to selected cells using IPv4toIPv6 formula.\n\n' +
    'Select the cells containing IPv4toIPv6 formulas.',
    ui.ButtonSet.OK_CANCEL
  );

  if (response !== ui.Button.OK) return;

  const numRows = selection.getNumRows();
  const numCols = selection.getNumColumns();
  let processed = 0;

  for (let r = 1; r <= numRows; r++) {
    for (let c = 1; c <= numCols; c++) {
      const targetCell = selection.getCell(r, c);
      if (copyFormattingForFormulaCell(targetCell)) {
        processed++;
      }
    }
  }

  ui.alert('Formatting copied to ' + processed + ' cell(s)!');
}

/**
 * Copies formatting to a cell containing an IPv4toIPv6 formula.
 */
function copyFormattingForFormulaCell(targetCell) {
  const sheet = targetCell.getSheet();
  const formula = targetCell.getFormula();

  if (!formula || !formula.toUpperCase().includes('IPV4TOIPV6')) {
    return false;
  }

  const formulaMatch = formula.match(/IPv4toIPv6\s*\(\s*([A-Z$]+[0-9$]+)/i);
  if (!formulaMatch) {
    return false;
  }

  const sourceCellRef = formulaMatch[1];
  let sourceCell;
  try {
    sourceCell = sheet.getRange(sourceCellRef);
  } catch (e) {
    return false;
  }

  const sourceRichText = sourceCell.getRichTextValue();
  if (!sourceRichText) return false;

  const sourceText = sourceRichText.getText();
  const targetText = String(targetCell.getValue());

  if (!targetText) return false;

  const ipv4Match = sourceText.match(/^10\.([^.]+)\.([^.]+)\.([^.]+)$/);
  if (!ipv4Match) return false;

  const aaValue = ipv4Match[1];

  let aaOutLen;
  if (/^[A-Za-z]+$/.test(aaValue)) {
    aaOutLen = aaValue.length;
  } else {
    aaOutLen = String(parseInt(aaValue, 10)).length;
  }

  const bbOutLen = 2;
  const doubleColonPos = targetText.indexOf('::');
  if (doubleColonPos < 0) return false;

  const aabbLen = aaOutLen + bbOutLen;
  const prefixLen = doubleColonPos - aabbLen;
  if (prefixLen < 0) return false;

  const builder = SpreadsheetApp.newRichTextValue().setText(targetText);

  const dotPositions = [];
  for (let i = 0; i < sourceText.length; i++) {
    if (sourceText[i] === '.') dotPositions.push(i);
  }

  if (dotPositions.length < 3) return false;

  const aaStart = dotPositions[0] + 1;
  const bbStart = dotPositions[1] + 1;
  const cccStart = dotPositions[2] + 1;

  const aaStyle = sourceRichText.getTextStyle(aaStart, aaStart + 1);
  const bbStyle = sourceRichText.getTextStyle(bbStart, bbStart + 1);
  const cccStyle = cccStart < sourceText.length ?
    sourceRichText.getTextStyle(cccStart, cccStart + 1) : null;

  if (aaStyle) {
    builder.setTextStyle(prefixLen, prefixLen + aaOutLen, aaStyle);
  }

  if (bbStyle) {
    builder.setTextStyle(prefixLen + aaOutLen, doubleColonPos, bbStyle);
  }

  const cccOutStart = doubleColonPos + 2;
  if (cccStyle && cccOutStart < targetText.length) {
    builder.setTextStyle(cccOutStart, targetText.length, cccStyle);
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
    .addItem('Copy Formatting to IPv6', 'copyIPv4Formatting')
    .addToUi();
}
'''


def get_credentials():
    """Get credentials using application default credentials."""
    scopes = [
        'https://www.googleapis.com/auth/script.projects',
        'https://www.googleapis.com/auth/spreadsheets',
        'https://www.googleapis.com/auth/drive',
    ]
    credentials, project = google.auth.default(scopes=scopes)
    return credentials


def find_or_create_script_project(service, spreadsheet_id):
    """Find existing script project or create a new one bound to the spreadsheet."""
    # Try to list existing projects
    try:
        # Get the spreadsheet to find its Drive ID
        drive_service = build('drive', 'v3', credentials=service._http.credentials)

        # Search for Apps Script files attached to this spreadsheet
        query = f"mimeType='application/vnd.google-apps.script' and '{spreadsheet_id}' in parents"
        results = drive_service.files().list(q=query, fields="files(id, name)").execute()
        files = results.get('files', [])

        if files:
            # Use existing script project
            script_id = files[0]['id']
            print(f"Found existing script project: {script_id}")
            return script_id
    except HttpError as e:
        print(f"Note: Could not search for existing projects: {e}")

    # Create new script project bound to the spreadsheet
    request = {
        'title': 'IPv4toIPv6 Converter',
        'parentId': spreadsheet_id
    }

    response = service.projects().create(body=request).execute()
    script_id = response['scriptId']
    print(f"Created new script project: {script_id}")
    return script_id


def update_script_content(service, script_id, code):
    """Update the Apps Script project with the new code."""
    request = {
        'files': [
            {
                'name': 'Code',
                'type': 'SERVER_JS',
                'source': code
            },
            {
                'name': 'appsscript',
                'type': 'JSON',
                'source': json.dumps({
                    'timeZone': 'Australia/Sydney',
                    'dependencies': {},
                    'exceptionLogging': 'STACKDRIVER',
                    'runtimeVersion': 'V8'
                })
            }
        ]
    }

    response = service.projects().updateContent(
        scriptId=script_id,
        body=request
    ).execute()

    print("Updated script content successfully")
    return response


def main():
    """Main function to deploy the Apps Script."""
    print("Getting credentials...")
    credentials = get_credentials()

    print("Building Apps Script service...")
    service = build('script', 'v1', credentials=credentials)

    print(f"Finding or creating script project for spreadsheet {SPREADSHEET_ID}...")
    script_id = find_or_create_script_project(service, SPREADSHEET_ID)

    print("Updating script content...")
    update_script_content(service, script_id, APPS_SCRIPT_CODE)

    print("\nDeployment complete!")
    print(f"Script project ID: {script_id}")
    print("Open the spreadsheet and refresh to see the 'IPv4/IPv6 Tools' menu")


if __name__ == '__main__':
    main()
