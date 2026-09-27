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

module.exports = {
  decodeCookieValue,
  deriveQidFromCookieQ,
};
