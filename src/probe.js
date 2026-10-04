/**
 * 真实可用性探测（mihomo / Clash.Meta 内核）
 *
 * 为什么需要它：
 *   tcp-ping 只做 TCP 三次握手。Cloudflare 的 IP（104.x / 172.6x / 162.159.x）
 *   和 *.workers.dev 域名对任何端口都接受 TCP 连接，所以这类节点 100% 会
 *   "通过验证"，但实际发起代理请求时因为 UUID / WS path / Host 参数失效而
 *   完全不能用。实测某份 656 节点的配置里，28% 属于这种假通过；914 节点
 *   那份更是 48.5%。
 *
 * 做法：
 *   1. 把候选节点转成 Clash proxy 对象，写一份最小可用的 mihomo 配置
 *   2. 拉起 mihomo，等 external-controller 就绪
 *   3. 逐个调 GET /proxies/{name}/delay?url=<测速链接>，
 *      让内核真正走一次代理请求访问测速链接
 *   4. 回填真实延迟，区分 available / failed：
 *        - 请求失败或超时 → failed
 *        - 实测延迟 > maxDelayMs → 直接剔除（归入 failed 并标记 too_slow）
 *
 * 测速链接：https://www.gstatic.com/generate_204
 *   （config.testUrl 全局唯一真源，可用 TEST_URL 环境变量覆盖）
 *
 * 注意：GitHub Actions runner 的出口 IP 属于 Azure 段，个别机场会屏蔽云厂商
 * IP。这类节点会被判为失败——这是环境特性，不是脚本缺陷。
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import yaml from 'js-yaml';
import config from './config.js';
import { toClashProxy, PROJECT_ROOT } from './exporter.js';

// mihomo 不认识的 type 会导致内核直接拒绝启动，必须先过滤
const SUPPORTED_TYPES = new Set([
    'ss', 'ssr', 'vmess', 'vless', 'trojan',
    'hysteria', 'hysteria2', 'tuic', 'anytls',
    'http', 'socks5', 'snell', 'wireguard'
]);

const DEFAULT_TEST_URL = 'https://www.gstatic.com/generate_204';

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * 探测配置：可被 config.validator.probe 覆盖
 *
 * 测速链接优先级：环境变量 TEST_URL > config.testUrl(全局唯一真源) >
 * config.validator.probe.testUrl > 内置默认值。
 */
function probeOptions() {
    const p = config.validator?.probe || {};
    return {
        bin: process.env.MIHOMO_BIN || p.bin || path.join(PROJECT_ROOT, 'bin', 'mihomo'),
        apiPort: Number(process.env.MIHOMO_API_PORT || p.apiPort || 9090),
        mixedPort: Number(p.mixedPort || 7899),
        timeoutMs: Number(p.timeoutMs || 5000),
        concurrency: Number(p.concurrency || 32),
        testUrl: process.env.TEST_URL || config.testUrl || p.testUrl || DEFAULT_TEST_URL,
        // 延迟上限：经测速链接实测超过该值 → 直接剔除
        maxDelayMs: Number(process.env.MAX_DELAY_MS || p.maxDelayMs || 0),
        workDir: path.join(PROJECT_ROOT, p.workDir || '.probe'),
        startupTimeoutMs: Number(p.startupTimeoutMs || 60000)
    };
}

/** 极简 HTTP GET，避免额外依赖 */
async function httpGet(url, timeoutMs = 8000) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
        const res = await fetch(url, { signal: ac.signal });
        const text = await res.text();
        let body = null;
        try { body = JSON.parse(text); } catch { body = text; }
        return { status: res.status, body };
    } catch (e) {
        return { status: 0, body: null, error: e.name === 'AbortError' ? 'timeout' : e.message };
    } finally {
        clearTimeout(timer);
    }
}

/**
 * 生成 mihomo 运行配置
 */
function buildMihomoConfig(proxies, opts) {
    const names = proxies.map(p => p.name);
    return {
        'mixed-port': opts.mixedPort,
        'allow-lan': false,
        mode: 'rule',
        'log-level': 'warning',
        'external-controller': `127.0.0.1:${opts.apiPort}`,
        // 关闭不必要的子系统，缩短启动时间、减少噪音
        profile: { 'store-selected': false, 'store-fake-ip': false },
        dns: { enable: false },
        proxies,
        'proxy-groups': [
            { name: 'PROBE', type: 'select', proxies: names }
        ],
        rules: ['MATCH,PROBE']
    };
}

/**
 * 拉起 mihomo 并等待 API 就绪
 */
/**
 * 判断给定文件是「需要解释器执行的脚本」还是「原生可执行文件」
 *  - 真实 mihomo 是 ELF/PE 原生二进制 → 直接 spawn
 *  - 测试替身 / 用户自备的 .js/.cjs/.mjs 包装 → 用 node 执行
 * Windows 下 spawn 无法直接执行带 shebang 的脚本，必须区分。
 */
function needsInterpreter(binPath) {
    if (/\.(m?js|cjs)$/i.test(binPath)) return true;
    try {
        const fd = fs.openSync(binPath, 'r');
        const buf = Buffer.alloc(2);
        fs.readSync(fd, buf, 0, 2, 0);
        fs.closeSync(fd);
        return buf.toString('latin1') === '#!';
    } catch {
        return false;
    }
}

async function startMihomo(opts) {
    if (!fs.existsSync(opts.bin)) {
        throw new Error(`mihomo binary not found: ${opts.bin}`);
    }

    fs.mkdirSync(opts.workDir, { recursive: true });
    const logPath = path.join(opts.workDir, 'mihomo.log');
    const logStream = fs.openSync(logPath, 'w');

    const args = ['-d', opts.workDir, '-f', path.join(opts.workDir, 'mihomo.yaml')];
    const isScript = needsInterpreter(opts.bin);
    const cmd = isScript ? process.execPath : opts.bin;
    const argv = isScript ? [opts.bin, ...args] : args;

    const child = spawn(cmd, argv, {
        stdio: ['ignore', logStream, logStream],
        detached: false
    });

    let exited = null;
    let spawnError = null;
    child.on('exit', (code, signal) => { exited = { code, signal }; });
    // 必须监听 error：spawn 失败（ENOENT/EACCES）会 emit 'error'，
    // 没有监听器时 Node 会直接抛未捕获异常让进程崩掉。
    child.on('error', (e) => { spawnError = e; });

    const base = `http://127.0.0.1:${opts.apiPort}`;
    const deadline = Date.now() + opts.startupTimeoutMs;

    while (Date.now() < deadline) {
        if (spawnError) {
            throw new Error(`cannot spawn mihomo (${spawnError.code}): ${opts.bin}`);
        }
        if (exited) {
            const log = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8').slice(-2000) : '';
            throw new Error(`mihomo exited early (code=${exited.code}) — log tail:\n${log}`);
        }
        const r = await httpGet(`${base}/version`, 3000);
        if (r.status === 200) {
            return { child, base, logPath, logStream, version: r.body?.version };
        }
        await sleep(500);
    }

    try { child.kill('SIGKILL'); } catch { /* ignore */ }
    const log = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8').slice(-2000) : '';
    throw new Error(`mihomo API not ready in ${opts.startupTimeoutMs}ms — log tail:\n${log}`);
}

function stopMihomo(proc) {
    if (!proc) return Promise.resolve();
    return new Promise((resolve) => {
        let done = false;
        const finish = () => { if (!done) { done = true; resolve(); } };

        proc.child.once('exit', finish);
        try { proc.child.kill('SIGTERM'); } catch { /* ignore */ }

        // 2s 后仍未退出则强杀；再等 1s 兜底
        setTimeout(() => {
            try { proc.child.kill('SIGKILL'); } catch { /* ignore */ }
        }, 2000).unref?.();
        setTimeout(() => {
            try { fs.closeSync(proc.logStream); } catch { /* ignore */ }
            finish();
        }, 3000).unref?.();
    });
}

/**
 * 测试单个节点（走内核，真实代理请求）
 * @returns {Promise<{delay:number, error?:string}>}
 */
async function testOne(base, name, opts) {
    const url = `${base}/proxies/${encodeURIComponent(name)}/delay` +
        `?url=${encodeURIComponent(opts.testUrl)}&timeout=${opts.timeoutMs}`;
    const r = await httpGet(url, opts.timeoutMs + 5000);

    if (r.status === 200 && typeof r.body?.delay === 'number') {
        return { delay: r.body.delay };
    }
    if (r.status === 504) return { delay: -1, error: 'timeout' };
    if (r.status === 404) return { delay: -1, error: 'proxy_not_found' };
    return { delay: -1, error: r.error || r.body?.message || `http_${r.status}` };
}

/**
 * 主入口：用 mihomo 真实探测节点可用性
 *
 * @param {object[]} nodes 内部统一格式的节点数组（parseNode 的输出）
 * @returns {Promise<{available:object[], failed:object[], skipped:number, tooSlow:number, testUrl:string}>}
 */
export async function probeNodes(nodes) {
    const opts = probeOptions();
    const total = nodes.length;

    // ---- 1. 转换 + 过滤内核不支持的协议 ----
    const seen = new Map();
    const pairs = [];   // [{ node, proxy }]
    let skipped = 0;

    for (const node of nodes) {
        const proxy = toClashProxy(node, seen);
        if (!proxy) { skipped++; continue; }
        if (!SUPPORTED_TYPES.has(proxy.type)) { skipped++; continue; }
        pairs.push({ node, proxy });
    }

    if (pairs.length === 0) {
        console.warn('[probe] no probeable nodes after conversion.');
        return { available: [], failed: nodes.slice(), skipped };
    }

    console.log(`[probe] ${pairs.length} probeable nodes (skipped ${skipped}).`);
    console.log(`[probe] test url: ${opts.testUrl}`);

    // ---- 2. 写配置、起内核 ----
    // 必须先建目录：startMihomo 里的 mkdir 在写配置之后才执行，
    // 首次运行（.probe 不存在）会直接 ENOENT。
    fs.mkdirSync(opts.workDir, { recursive: true });

    const cfg = buildMihomoConfig(pairs.map(p => p.proxy), opts);
    fs.writeFileSync(
        path.join(opts.workDir, 'mihomo.yaml'),
        yaml.dump(cfg, { lineWidth: -1, noRefs: true }),
        'utf8'
    );

    let proc = null;
    const results = [];
    try {
        proc = await startMihomo(opts);
        console.log(`[probe] mihomo ready (version ${proc.version || '?'}) at ${proc.base}`);

        // ---- 3. 分批并发测试 ----
        const batch = Math.max(1, opts.concurrency);
        for (let i = 0; i < pairs.length; i += batch) {
            const slice = pairs.slice(i, i + batch);
            const rs = await Promise.all(
                slice.map(async ({ node, proxy }) => {
                    const r = await testOne(proc.base, proxy.name, opts);
                    return { node, proxy, ...r };
                })
            );
            results.push(...rs);

            const done = Math.min(i + batch, pairs.length);
            if (done % (batch * 5) === 0 || done === pairs.length) {
                const ok = results.filter(x => x.delay > 0).length;
                console.log(`[probe] ${done}/${pairs.length} tested, ${ok} alive`);
            }
        }
    } catch (e) {
        console.error(`[probe] fatal: ${e.message}`);
        // 内核整体失败 → 全部标记为未验证，交由上层决定是否回退
        return { available: [], failed: [], skipped, fatal: e.message, testUrl: opts.testUrl };
    } finally {
        await stopMihomo(proc);
    }

    // ---- 4. 回填真实延迟，并按测速链接的延迟上限剔除 ----
    const available = [];
    const failed = [];
    const maxDelayMs = opts.maxDelayMs > 0 ? opts.maxDelayMs : Infinity;
    let tooSlow = 0;

    for (const r of results) {
        r.node.delay = r.delay;
        const reachable = r.delay > 0;
        const slow = reachable && r.delay > maxDelayMs;
        if (slow) tooSlow++;

        r.node.probe = {
            ok: reachable && !slow,
            delay: r.delay,
            testUrl: opts.testUrl,
            error: reachable
                ? (slow ? 'too_slow' : null)
                : (r.error || 'unreachable')
        };

        (r.node.probe.ok ? available : failed).push(r.node);
    }

    // 被跳过的节点（转换失败/协议不支持）算 failed，便于排查
    for (const node of nodes) {
        if (!pairs.some(p => p.node === node) && !results.some(r => r.node === node)) {
            if (!available.includes(node) && !failed.includes(node)) {
                node.delay = -1;
                node.probe = { ok: false, delay: -1, testUrl: opts.testUrl, error: 'unsupported_or_invalid' };
                failed.push(node);
            }
        }
    }

    console.log(
        `[probe] done via ${opts.testUrl}: ${available.length} available, ` +
        `${failed.length} failed (${tooSlow} too slow > ${maxDelayMs}ms), ${skipped} skipped.`
    );
    return { available, failed, skipped, tooSlow, testUrl: opts.testUrl };
}
