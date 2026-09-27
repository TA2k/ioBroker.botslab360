'use strict';

const { expect } = require('chai');
const { decodeCookieValue, deriveQidFromCookieQ } = require('./lib/auth');

describe('web session authentication helpers', () => {
  it('extracts a direct numeric QID from an encoded cookie', () => {
    const cookieQ = 'token%3Dsynthetic%26qid%3D123456789';

    expect(deriveQidFromCookieQ(cookieQ)).to.equal('123456789');
  });

  it('extracts a numeric QID from the synthetic user field', () => {
    const cookieQ = 'token=synthetic&u=360T987654321';

    expect(deriveQidFromCookieQ(cookieQ)).to.equal('987654321');
  });

  it('rejects a non-numeric QID without a supported fallback', () => {
    const cookieQ = 'token=synthetic&qid=not-a-number&u=synthetic-user';

    expect(deriveQidFromCookieQ(cookieQ)).to.equal(null);
  });

  it('keeps malformed URL encoding intact', () => {
    const cookieValue = 'synthetic%value';

    expect(decodeCookieValue(cookieValue)).to.equal(cookieValue);
  });
});
