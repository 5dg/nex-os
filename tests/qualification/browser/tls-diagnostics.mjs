// Only typed network outcomes are exportable. Never return error messages, URLs,
// IP addresses, response bodies, callback codes or browser storage.
import {lookup} from 'node:dns/promises';
import {connect} from 'node:net';

export function navigationFailure(error) {
  const code = String(error?.message || '').match(/\bnet::(ERR_[A-Z0-9_]{1,80})\b/)?.[1];
  return {outcome: 'rejected', code: code || (error?.name === 'TimeoutError' ? 'TIMEOUT' : 'UNCLASSIFIED_NAVIGATION_FAILURE')};
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
