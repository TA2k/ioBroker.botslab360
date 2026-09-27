'use strict';

function decodeCookieValue(value) {
  const stringValue = String(value || '');

  try {
    return decodeURIComponent(stringValue);
  } catch {
    return stringValue;
  }
}

function deriveQidFromCookieQ(cookieQ) {
  const decodedQ = decodeCookieValue(cookieQ);
  const params = new URLSearchParams(decodedQ);
  const directQid = String(params.get('qid') || '').trim();

  if (/^\d+$/.test(directQid)) {
    return directQid;
  }

  const source = params.get('u') || decodedQ;
  const match = source.match(/360[A-Za-z]?(\d+)/);

  return match ? match[1] : null;
}

// Split a full cookie string (e.g. a copied Cookie request header) into the values we need.
// Cookie names are matched case-insensitively because 360 uses uppercase Q/T.
function parseWebSessionCookie(cookieString) {
  const result = { q: '', t: '', qid: '' };

  for (const part of String(cookieString || '').split(';')) {
    const trimmed = part.trim();
    const separator = trimmed.indexOf('=');

    if (separator < 1) {
      continue;
    }

    const name = trimmed.slice(0, separator).trim().toLowerCase();
    const value = trimmed.slice(separator + 1).trim();

    if (name === 'q' || name === 't' || name === 'qid') {
      result[name] = value;
    }
  }

  return result;
}

module.exports = {
  decodeCookieValue,
  deriveQidFromCookieQ,
  parseWebSessionCookie,
};
