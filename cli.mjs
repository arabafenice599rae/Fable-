// Small wallet helper on the second implementation: key generation, addresses, signing.
//   node cli.mjs keygen <48-byte seed hex>
//   node cli.mjs wallet "<24 words>" <account> <index>
//   node cli.mjs sign <secret key hex> <32-byte message hex>
import * as F from './fable.mjs';

const [cmd, a, b, c] = process.argv.slice(2);
const hex = (x) => Buffer.from(x).toString('hex');
if (cmd === 'keygen') {
  const k = F.keygen(Buffer.from(a, 'hex'));
  console.log(JSON.stringify({ pk: hex(k.publicKey), sk: hex(k.secretKey) }));
} else if (cmd === 'wallet') {
  const k = F.keygen(F.keySeed(F.seedFromMnemonic(a), Number(b || 0), Number(c || 0)));
  console.log(JSON.stringify({ address: F.encodeAddress(F.address(Buffer.from(k.publicKey))), public_key: hex(k.publicKey) }));
} else if (cmd === 'sign') {
  console.log(hex(F.sign(Buffer.from(b, 'hex'), Buffer.from(a, 'hex'))));
} else {
  console.error('usage: node cli.mjs keygen|wallet|sign ...');
  process.exit(1);
}
