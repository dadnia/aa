import { test } from 'node:test';
import assert from 'node:assert';
import { extractLinks, decodeSubscription, parseNode, parseClash } from '../parser.js';
import { Buffer } from 'buffer';

test('extractLinks should find vmess links', (t) => {
    const text = 'Some text here vmess://eydhZGQnOiAnMTI3LjAuMC4xJ30= and more text';
    const links = extractLinks(text);
    assert.strictEqual(links.length, 1);
    assert.strictEqual(links[0], 'vmess://eydhZGQnOiAnMTI3LjAuMC4xJ30=');
});

// 回归：旧正则字符集缺 @ ? & # : . ，vless/trojan/ss 会被截断
test('extractLinks must NOT truncate vless/trojan/ss URIs', (t) => {
    const text = [
        'vless://uuid-1@1.2.3.4:443?security=tls&type=ws&path=%2Fws&host=a.com#HK-01',
        'trojan://pass%401@5.6.7.8:443?sni=b.com#SG-02',
        'ss://YWVzLTI1Ni1nY206cGFzcw==@9.9.9.9:8388#JP-03'
    ].join('\n');

    const links = extractLinks(text);
    assert.strictEqual(links.length, 3);
    assert.ok(links[0].includes('security=tls'), 'vless 参数被截断');
    assert.ok(links[0].includes('#HK-01'), 'vless 标签被截断');
    assert.ok(links[1].includes('#SG-02'), 'trojan 标签被截断');
    assert.ok(links[2].includes(':8388'), 'ss 端口被截断');
});

// 回归：HTML 不该被 base64 "解" 出内容
test('decodeSubscription must reject non-base64 / non-node content', (t) => {
    assert.deepStrictEqual(decodeSubscription('<html><body>hello</body></html>'), []);
    assert.deepStrictEqual(decodeSubscription('plain text, no nodes'), []);
});

test('decodeSubscription should decode base64', (t) => {
    const raw = 'vmess://abc\nvmess://def';
    const base64 = Buffer.from(raw).toString('base64');
    const links = decodeSubscription(base64);
    assert.strictEqual(links.length, 2);
    assert.strictEqual(links[0], 'vmess://abc');
});

test('parseNode should parse vmess json', (t) => {
    const config = { add: '1.2.3.4', port: 443, ps: 'test', id: 'uuid', net: 'ws', tls: 'tls' };
    const base64 = Buffer.from(JSON.stringify(config)).toString('base64');
    const link = `vmess://${base64}`;

    const node = parseNode(link);
    assert.strictEqual(node.type, 'vmess');
    assert.strictEqual(node.add, '1.2.3.4');
    assert.strictEqual(node.port, 443);
});

// 回归：ss/vless/trojan 必须带 add+port，否则 validator 必淘汰
test('parseNode must yield add/port for ss, vless, trojan', (t) => {
    const ss = parseNode('ss://YWVzLTI1Ni1nY206cGFzcw==@9.9.9.9:8388#JP');
    assert.strictEqual(ss.type, 'ss');
    assert.strictEqual(ss.add, '9.9.9.9');
    assert.strictEqual(ss.port, 8388);
    assert.strictEqual(ss.method, 'aes-256-gcm');
    assert.strictEqual(ss.password, 'pass');

    const vless = parseNode('vless://uuid-1@1.2.3.4:443?security=tls&type=ws&path=%2Fws#HK');
    assert.strictEqual(vless.type, 'vless');
    assert.strictEqual(vless.add, '1.2.3.4');
    assert.strictEqual(vless.port, 443);
    assert.strictEqual(vless.tls, true);
    assert.strictEqual(vless.network, 'ws');

    const trojan = parseNode('trojan://mypass@5.6.7.8:443?sni=b.com#SG');
    assert.strictEqual(trojan.type, 'trojan');
    assert.strictEqual(trojan.add, '5.6.7.8');
    assert.strictEqual(trojan.port, 443);
});

// 回归：crawler 会把 Clash 对象塞进集合，parseNode 不能崩
test('parseNode must not throw on object input', (t) => {
    const obj = { type: 'ss', add: '1.1.1.1', port: 8388, method: 'aes-128-gcm', password: 'p' };
    assert.strictEqual(parseNode(obj), obj);
    assert.strictEqual(parseNode(null).type, 'unknown');
});

// 回归：Clash YAML 必须转成含 add/port 的内部格式
test('parseClash must convert proxies to internal node format', (t) => {
    const yamlContent = `
proxies:
  - name: "HK: 01"
    type: vmess
    server: 1.2.3.4
    port: 443
    uuid: uuid-x
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: a.com
  - name: SG-02
    type: ss
    server: 5.6.7.8
    port: 8388
    cipher: aes-256-gcm
    password: pw
`;
    const nodes = parseClash(yamlContent);
    assert.strictEqual(nodes.length, 2);

    const vm = nodes.find(n => n.type === 'vmess');
    assert.strictEqual(vm.add, '1.2.3.4');
    assert.strictEqual(vm.port, 443);
    assert.strictEqual(vm.config.net, 'ws');
    assert.strictEqual(vm.config.path, '/ws');

    const ss = nodes.find(n => n.type === 'ss');
    assert.strictEqual(ss.add, '5.6.7.8');
    assert.strictEqual(ss.method, 'aes-256-gcm');
    assert.strictEqual(ss.password, 'pw');
});
