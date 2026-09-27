'use strict';

const { expect } = require('chai');
const { decodeCookieValue, deriveQidFromCookieQ, parseWebSessionCookie } = require('./lib/auth');

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

  it('splits a full document.cookie string into q, t and qid', () => {
    const cookieString = 'q=q-value; t=t-value; qid=123456789; other=ignored';

    expect(parseWebSessionCookie(cookieString)).to.deep.equal({
      q: 'q-value',
      t: 't-value',
      qid: '123456789',
    });
  });

  it('matches the uppercase Q and T cookie names used by 360', () => {
    const cookieString = '__NS_Q=ignored; Q=u%3D360H1; T=s%3D514e; __guid=x';

    const parsed = parseWebSessionCookie(cookieString);

    expect(parsed.q).to.equal('u%3D360H1');
    expect(parsed.t).to.equal('s%3D514e');
  });

  it('keeps the full value when it contains equals signs', () => {
    const cookieString = 't=a=b==; q=token%3Dsynthetic';

    const parsed = parseWebSessionCookie(cookieString);

    expect(parsed.t).to.equal('a=b==');
    expect(parsed.q).to.equal('token%3Dsynthetic');
  });

  it('returns empty values when q and t are missing', () => {
    expect(parseWebSessionCookie('foo=bar; baz=qux')).to.deep.equal({
      q: '',
      t: '',
      qid: '',
    });
  });
});
