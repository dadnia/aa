import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';
import config from './config.js';

// ============================================================
// 路径锚定：所有相对路径统一相对【项目根目录】解析，
// 而不是相对 process.cwd()。避免从其他目录启动时输出散落。
// ============================================================
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, '..');

function resolveOut(p) {
    return path.isAbsolute(p) ? p : path.resolve(PROJECT_ROOT, p);
}

function ensureDir(dir) {
    const d = resolveOut(dir);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    return d;
}

/**
 * 生成唯一且安全的 Clash 节点名
 *  - Clash 要求 proxies[].name 全局唯一，重名会导致配置加载失败
 *  - 名字里的 : # 等字符由 js-yaml 自动加引号，但重复名不会
 */
function safeName(node, seen) {
    const base = String(node.ps || node.name || `${node.type}-${node.add || node.server || 'unknown'}`)
        .replace(/[\r\n\t]+/g, ' ')
        .trim() || 'node';
    const delay = Number.isFinite(node.delay) && node.delay > 0 ? `${node.delay}ms` : 'unchecked';
    let name = `${base} - ${delay}`;
    const n = seen.get(name) || 0;
    seen.set(name, n + 1);
    if (n > 0) name = `${name} #${n + 1}`;
    return name;
}

/**
 * 将内部节点对象转换为 Clash Proxy
 * 修复点：原实现只处理 vmess，ss/vless/trojan 全部 return null 被静默丢弃。
 * @param {object} node
 * @param {Map} seen 名称去重表
 */
export function toClashProxy(node, seen = new Map()) {
    if (!node || typeof node !== 'object') return null;

    const server = node.add || node.server;
    const port = Number(node.port);
    if (!server || !port) return null;

    const name = safeName(node, seen);
    const base = { name, server, port, udp: true };

    switch (node.type) {
        case 'vmess': {
            const c = node.config || {};
            const proxy = {
                ...base,
                type: 'vmess',
                uuid: node.id || c.id,
                alterId: Number(c.aid ?? c.alterId ?? 0),
                cipher: c.scy || 'auto',
                tls: c.tls === 'tls' || c.tls === true,
                network: c.net || 'tcp',
                'skip-cert-verify': true
            };
            if (!proxy.uuid) return null;
            if (proxy.network === 'ws') {
                proxy['ws-opts'] = {
                    path: c.path || '/',
                    headers: { Host: c.host || server }
                };
            } else if (proxy.network === 'grpc') {
                proxy['grpc-opts'] = { 'grpc-service-name': c.path || '' };
            }
            return proxy;
        }

        case 'ss':
            if (!node.method || !node.password) return null;
            return { ...base, type: 'ss', cipher: node.method, password: node.password };

        case 'ssr':
            if (!node.method || !node.password) return null;
            return {
                ...base,
                type: 'ssr',
                cipher: node.method,
                password: node.password,
                protocol: node.protocol || 'origin',
                obfs: node.obfs || 'plain',
                'protocol-param': '',
                'obfs-param': ''
            };

        case 'vless': {
            if (!node.uuid) return null;
            const proxy = {
                ...base,
                type: 'vless',
                uuid: node.uuid,
                tls: !!node.tls,
                servername: node.sni || server,
                network: node.network || 'tcp',
                flow: node.flow || '',
                'skip-cert-verify': true
            };
            if (proxy.network === 'ws') {
                proxy['ws-opts'] = { path: node.path || '/', headers: { Host: node.host || server } };
            } else if (proxy.network === 'grpc') {
                proxy['grpc-opts'] = { 'grpc-service-name': node.path || '' };
            }
            return proxy;
        }

        case 'trojan': {
            if (!node.password) return null;
            const proxy = {
                ...base,
                type: 'trojan',
                password: node.password,
                sni: node.sni || server,
                network: node.network || 'tcp',
                'skip-cert-verify': true
            };
            if (proxy.network === 'ws') {
                proxy['ws-opts'] = { path: node.path || '/', headers: { Host: node.host || server } };
            }
            return proxy;
        }

        case 'hysteria2':
        case 'hysteria':
            if (!node.password) return null;
            return { ...base, type: 'hysteria2', password: node.password, sni: node.sni || server, 'skip-cert-verify': true };

        default:
            return null;
    }
}

/**
 * 组装完整 Clash 配置
 *   url-test 组的健康检查地址统一取全局测速链接 config.testUrl，
 *   保证「导出配置里被选中的节点」和「探测时验证过的节点」用的是同一个靶点。
 */
function buildClashConfig(proxies) {
    const names = proxies.map(p => p.name);
    const testUrl = config.testUrl || config.validator?.probe?.testUrl
        || 'https://www.gstatic.com/generate_204';
    return {
        port: 7890,
        'socks-port': 7891,
        'allow-lan': true,
        mode: 'Rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        proxies,
        'proxy-groups': [
            {
                name: 'Auto Select',
                type: 'url-test',
                proxies: names,
                url: testUrl,
                interval: 300,
                tolerance: 50
            },
            {
                name: 'Proxy',
                type: 'select',
                proxies: ['Auto Select', ...names]
            }
        ],
        rules: ['MATCH,Proxy']
    };
}

/**
 * 导出为 Clash 配置文件
 *
 * 修复点：proxies 为空时删除旧的同名文件，而不是直接 return。
 * 否则上一轮的旧数据会残留，被误认为本次运行成功。
 *
 * @param {object[]} nodes
 * @param {string} fileName
 */
export async function exportClash(nodes, fileName = config.output.clashFileName) {
    const dir = ensureDir(config.output.dir);
    const filePath = path.join(dir, fileName);

    const seen = new Map();
    const proxies = (nodes || [])
        .map(n => toClashProxy(n, seen))
        .filter(p => p !== null);

    if (proxies.length === 0) {
        console.warn(`[exportClash] 0 proxies for ${fileName}; removing stale file if any.`);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        return 0;
    }

    const yamlStr = yaml.dump(buildClashConfig(proxies), {
        lineWidth: -1,     // 不折行，避免长 base64/路径被折断
        noRefs: true,      // 不生成 &anchor/*alias，Clash 不认
        quotingType: '"',
        forceQuotes: false
    });
    fs.writeFileSync(filePath, yamlStr, 'utf8');
    console.log(`Clash config exported to ${filePath} (${proxies.length} proxies)`);
    return proxies.length;
}

/**
 * 导出为 Base64 订阅文件
 * @param {object[]} nodes
 * @param {string} fileName
 */
export async function exportSubscribe(nodes, fileName = config.output.subscribeFileName) {
    const dir = ensureDir(config.output.dir);
    const filePath = path.join(dir, fileName);

    // 只导出原始字符串链接；Clash 对象节点无法还原成 URI，跳过
    const links = (nodes || [])
        .map(n => (typeof n?.original === 'string' ? n.original : null))
        .filter(Boolean);

    if (links.length === 0) {
        console.warn(`[exportSubscribe] 0 links for ${fileName}; removing stale file if any.`);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        return 0;
    }

    const base64Content = Buffer.from(links.join('\n'), 'utf8').toString('base64');
    fs.writeFileSync(filePath, base64Content, 'utf8');
    console.log(`Subscription file exported to ${filePath} (${links.length} links)`);
    return links.length;
}

/**
 * 保存运行日志
 * @param {object} stats
 */
export async function saveRunLog(stats) {
    const dir = ensureDir(config.output.dir);
    // logDir 留空时自动跟随 output.dir，避免改 dir 后日志写到别处
    const logDir = ensureDir(config.output.logDir || path.join(config.output.dir, 'logs'));

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = `run_${timestamp}.log`;
    const filePath = path.join(logDir, fileName);

    const logContent = `
=== Spider-Clash Run Log ===
Date: ${new Date().toISOString()}
Duration: ${stats.duration}ms

[Speed Test]
Test Url: ${stats.testUrl || config.testUrl || '(unset)'}
Nodes Probed (real proxy request): ${stats.probedNodes ?? 0}
Nodes Rejected (unreachable or too slow): ${stats.probeFailedNodes ?? 0}
  of which too slow: ${stats.tooSlowNodes ?? 0}
Probe Fatal: ${stats.probeFatal || 'none'}

[Statistics]
Total Raw Links Found: ${stats.totalLinks}
Valid Format Nodes: ${stats.validFormatNodes}
Validated Available Nodes: ${stats.availableNodes}

[Errors]
${stats.errors && stats.errors.length > 0 ? stats.errors.join('\n') : 'None'}

[Config]
Sources: ${JSON.stringify(config.sources, null, 2)}
============================
`.trim();

    fs.writeFileSync(filePath, logContent, 'utf8');
    console.log(`Run log saved to ${filePath}`);
    return filePath;
}

export async function saveResults(nodes) {
    await exportClash(nodes);
    await exportSubscribe(nodes);
}

export { resolveOut, PROJECT_ROOT };
