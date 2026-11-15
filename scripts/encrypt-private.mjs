// 나만의 서랍: data/private.json(커밋하지 않음)을 숫자 비밀번호로 암호화해 data/private.enc를 만든다.
// 사용: node scripts/encrypt-private.mjs   → 비밀번호를 두 번 입력(화면에 보이지 않음)
// 브라우저(index.html)는 같은 방식(PBKDF2-SHA256 → AES-256-GCM)으로 푼다.
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'data/private.json');
const OUT = join(ROOT, 'data/private.enc');
const ITER = 600000;

function askHidden(question) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    process.stdout.write(question);
    if (!stdin.isTTY) { // 파이프 입력(테스트용)
      let buf = '';
      stdin.setEncoding('utf8');
      stdin.on('data', (c) => { buf += c; });
      stdin.on('end', () => { process.stdout.write('\n'); resolve(buf.split('\n')); });
      return;
    }
    let value = '';
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    const onData = (ch) => {
      if (ch === '\r' || ch === '\n') { stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData); process.stdout.write('\n'); resolve(value); }
      else if (ch === '\u0003') { process.stdout.write('\n'); process.exit(1); }
      else if (ch === '\u007f') { value = value.slice(0, -1); }
      else { value += ch; }
    };
    stdin.on('data', onData);
  });
}

const b64 = (buf) => Buffer.from(buf).toString('base64');

const data = JSON.parse(readFileSync(SRC, 'utf8'));
delete data._note;

let pin, again;
if (process.stdin.isTTY) {
  pin = await askHidden('서랍 비밀번호(숫자 4자리): ');
  again = await askHidden('한 번 더: ');
} else {
  [pin, again] = await askHidden('');
  if (!pin) {
    console.error('비밀번호를 입력받을 수 없는 환경입니다. 일반 터미널 창에서 실행해 주세요:\n  cd ~/projects/dashboard && node scripts/encrypt-private.mjs');
    process.exit(1);
  }
}
pin = (pin || '').trim(); again = (again || '').trim();
if (!/^\d{4}$/.test(pin)) { console.error('숫자 4자리로 입력해 주세요.'); process.exit(1); }
if (pin !== again) { console.error('두 번 입력한 비밀번호가 다릅니다.'); process.exit(1); }

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(data)));

writeFileSync(OUT, JSON.stringify({ v: 1, kdf: 'PBKDF2-SHA256', iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) }) + '\n');
console.log(`data/private.enc 저장 완료 (앱 ${data.apps.length}개). 이 파일만 커밋한다.`);
