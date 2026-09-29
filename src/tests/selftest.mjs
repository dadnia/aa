#!/usr/bin/env node
// 无依赖自检：直接断言，不依赖 node:test 子进程，也不需要 npm install
//   node src/tests/selftest.mjs
import assert from 'node:assert';
import { Buffer } from 'buffer';
import { extractLinks, decodeSubscription, parseNode, parseClash } from '../parser.js';

let pass = 0, fail = 0;
const cases = [];
const t = (name, fn) => cases.push([name, fn]);

t('extractLinks 提取 vmess', () => {
    const links = extractLinks('text vmess://eydhZGQnOiAnMTI3LjAuMC4xJ30= more');
    assert.strictEqual(links.length, 1);
});

t('extractLinks 不截断 vless/trojan/ss（旧正则会把参数切掉）', () => {
    const text = [
        'vless://uuid-1@1.2.3.4:443?security=tls&type=ws&path=%2Fws&host=a.com#HK-01',
        'trojan://pass%401@5.6.7.8:443?sni=b.com#SG-02',
        'ss://YWVzLTI1Ni1nY206cGFzcw==@9.9.9.9:8388#JP-03'
    ].join('\n');
    const links = extractLinks(text);
    assert.strictEqual(links.length, 3);
    assert.ok(links[0].includes('security=tls'));
    assert.ok(links[0].includes('#HK-01'));
    assert.ok(links[1].includes('#SG-02'));
    assert.ok(links[2].includes(':8388'));
});

t('decodeSubscription 拒绝 HTML / 明文', () => {
    assert.deepStrictEqual(decodeSubscription('<html><body>hi</body></html>'), []);
    assert.deepStrictEqual(decodeSubscription('plain text'), []);
});

t('decodeSubscription 正常解码', () => {
    const b64 = Buffer.from('vmess://abc\nvmess://def').toString('base64');
    assert.strictEqual(decodeSubscription(b64).length, 2);
});

t('parseNode 解析 vmess', () => {
    const cfg = { add: '1.2.3.4', port: 443, ps: 't', id: 'u', net: 'ws', tls: 'tls' };
    const n = parseNode(`vmess://${Buffer.from(JSON.stringify(cfg)).toString('base64')}`);
    assert.strictEqual(n.type, 'vmess');
    assert.strictEqual(n.add, '1.2.3.4');
    assert.strictEqual(n.port, 443);
});

t('parseNode 对 ss/vless/trojan 产出 add+port', () => {
    const ss = parseNode('ss://YWVzLTI1Ni1nY206cGFzcw==@9.9.9.9:8388#JP');
    assert.strictEqual(ss.add, '9.9.9.9');
    assert.strictEqual(ss.port, 8388);
    assert.strictEqual(ss.method, 'aes-256-gcm');
    assert.strictEqual(ss.password, 'pass');

    const vl = parseNode('vless://uuid-1@1.2.3.4:443?security=tls&type=ws&path=%2Fws#HK');
    assert.strictEqual(vl.add, '1.2.3.4');
    assert.strictEqual(vl.port, 443);
    assert.strictEqual(vl.tls, true);

    const tj = parseNode('trojan://mypass@5.6.7.8:443?sni=b.com#SG');
    assert.strictEqual(tj.add, '5.6.7.8');
    assert.strictEqual(tj.port, 443);
});

t('parseNode 对对象/空值不崩', () => {
    const o = { type: 'ss', add: '1.1.1.1', port: 8388 };
    assert.strictEqual(parseNode(o), o);
    assert.strictEqual(parseNode(null).type, 'unknown');
});

t('parseClash 转内部格式', () => {
    const y = `
proxies:
  - name: "HK: 01"
    type: vmess
    server: 1.2.3.4
    port: 443
    uuid: u
    network: ws
    ws-opts: { path: /ws, headers: { Host: a.com } }
  - name: SG
    type: ss
    server: 5.6.7.8
    port: 8388
    cipher: aes-256-gcm
    password: pw
`;
    const nodes = parseClash(y);
    assert.strictEqual(nodes.length, 2);
    assert.strictEqual(nodes.find(n => n.type === 'ss').add, '5.6.7.8');
});

for (const [name, fn] of cases) {
    try { fn(); pass++; console.log(`  ok  ${name}`); }
    catch (e) { fail++; console.log(`  FAIL ${name}\n       ${e.message}`); }
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
