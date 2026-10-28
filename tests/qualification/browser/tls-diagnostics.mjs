// Only typed network outcomes are exportable. Never return error messages, URLs,
// IP addresses, response bodies, callback codes or browser storage.
import {lookup} from 'node:dns/promises';
import {connect} from 'node:net';

export function navigationFailure(error) {
  const code = String(error?.message || '').match(/\bnet::(ERR_[A-Z0-9_]{1,80})\b/)?.[1];
  return {outcome: 'rejected', code: code || (error?.name === 'TimeoutError' ? 'TIMEOUT' : 'UNCLASSIFIED_NAVIGATION_FAILURE')};
}

export function requestTLSFailure(error) {
  const known = ['UNABLE_TO_VERIFY_LEAF_SIGNATURE','SELF_SIGNED_CERT_IN_CHAIN','DEPTH_ZERO_SELF_SIGNED_CERT','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','CERT_HAS_EXPIRED','ERR_TLS_CERT_ALTNAME_INVALID','ECONNREFUSED','ENOTFOUND','ETIMEDOUT'];
  if (known.includes(error?.code)) return error.code;
  const message = String(error?.message || '');
  // Playwright wraps native TLS errors without preserving error.code. Export
  // only a fixed classification, never its URL-bearing error message.
  if (/unable to verify (?:the first certificate|leaf signature)/i.test(message)) return 'UNABLE_TO_VERIFY_LEAF_SIGNATURE';
  if (/unable to get local issuer certificate/i.test(message)) return 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY';
  if (/self.signed certificate/i.test(message)) return 'SELF_SIGNED_CERT_IN_CHAIN';
  if (/certificate has expired/i.test(message)) return 'CERT_HAS_EXPIRED';
  return 'UNCLASSIFIED_REQUEST_FAILURE';
}

export async function listenerProbe(address) {
  const target = new URL(address);
  if (target.protocol !== 'https:' || target.username || target.password) throw new Error('Explicit HTTPS fixture endpoint required');
  const result = {dns: 'unavailable', tcp: 'not attempted'};
  let timer;
  try {
    const addresses = await Promise.race([
      lookup(target.hostname, {all: true}),
      new Promise((_, reject) => {timer = setTimeout(() => reject(new Error('DNS budget')), 3000);}),
    ]);
    result.dns = 'resolved';
    result.addressFamilies = [...new Set(addresses.map(address => address.family))].sort();
  } catch {
    return result;
  } finally {clearTimeout(timer);}
  result.tcp = await new Promise(resolve => {
    const socket = connect({host: target.hostname, port: Number(target.port || 443)});
    const finish = outcome => {socket.destroy(); resolve(outcome);};
    socket.setTimeout(3000, () => finish('timeout'));
    socket.once('connect', () => finish('connected'));
    socket.once('error', error => finish(['ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH', 'ENOTFOUND', 'EAI_AGAIN'].includes(error.code) ? error.code : 'unavailable'));
  });
  return result;
}

export async function navigationProbe(page, address) {
  try {
    const response = await page.goto(address, {timeout: 8000});
    return {outcome: 'responded', status: response?.status() ?? null};
  } catch (error) {return navigationFailure(error);}
}
