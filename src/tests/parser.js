import { Buffer } from 'buffer';
import yaml from 'js-yaml';

// 非全局版本，用于 .test() 检测（带 g 的正则 .test() 会记忆 lastIndex）
const LINK_TEST = /\b(?:vmess|vless|ss|ssr|trojan|hysteria2?|hy2|tuic):\/\//i;

// 全局版本用于提取；每次调用重建，避免 lastIndex 污染
function linkRegex() {
    // 关键修复：字符集不再排除 @ ? & # % : . 等参数分隔符，
    // 否则 vless/trojan/ss 会在第一个 : 或 @ 处被截断。
    return /\b(?:vmess|vless|ss|ssr|trojan|hysteria2?|hy2|tuic):\/\/[^\s"'<>\\`)\]}]+/gi;
}

/**
 * 解析 Base64 编码的订阅内容
 *
 * 修复点：原实现无条件对任意字符串做 base64 解码，HTML 也能"解"出乱码行，
 * 导致调用方 `if (links.length > 0)` 恒真，明文订阅永远走不到 extractLinks。
 * 现在加入字符集校验 + 解码后协议校验，失败返回 []。
 *
 * @param {string} content
 * @returns {string[]} 解码后的节点链接列表
 */
export function decodeSubscription(content) {
    if (typeof content !== 'string') return [];
    try {
        const cleaned = content.trim().replace(/\s/g, '');
        if (cleaned.length < 8) return [];
        // base64 字符集校验（含 URL-safe 变体）
        if (!/^[A-Za-z0-9+/=_-]+$/.test(cleaned)) return [];

        const decoded = Buffer.from(cleaned, 'base64').toString('utf-8');
        // 解码结果必须真的含节点协议，否则视为解码失败
        if (!LINK_TEST.test(decoded)) return [];

        return decoded
            .split(/[\r\n]+/)
            .map(l => l.trim())
            .filter(Boolean);
    } catch (error) {
        console.error('Base64 decode failed:', error.message);
        return [];
    }
}

/**
 * 从文本中通过正则提取节点链接
 * @param {string} text
 * @returns {string[]}
 */
export function extractLinks(text) {
    if (typeof text !== 'string') return [];
    const matches = text.match(linkRegex()) || [];
    // 去掉行尾可能被粘上的标点
    return matches.map(s => s.replace(/[.,;、。]+$/, '')).filter(Boolean);
}

/**
 * 解析单个节点链接为内部统一对象
 *
 * 修复点：原实现对 ss/vless/trojan 只返回 { type, original }，没有 add/port，
 * 导致 validator 里 `if (!node.port || !node.add)` 恒真，这些节点必然被淘汰。
 *
 * 同时兼容「已是对象」的输入（crawler 从 Clash YAML 解析出的节点），
 * 直接原样透传，避免 `link.startsWith is not a function` 崩溃。
 *
 * @param {string|object} link
 */
export function parseNode(link) {
    if (link && typeof link === 'object') {
        return link.type ? link : { type: 'unknown', original: link, error: 'not_string' };
    }
    if (typeof link !== 'string') {
        return { type: 'unknown', original: link, error: 'not_string' };
    }

    if (link.startsWith('vmess://')) return parseVmess(link);
    if (link.startsWith('ss://')) return parseSS(link);
    if (link.startsWith('ssr://')) return parseSSR(link);
    if (link.startsWith('vless://')) return parseURI(link, 'vless');
    if (link.startsWith('trojan://')) return parseURI(link, 'trojan');
    if (/^(hysteria2|hy2):\/\//i.test(link)) return parseURI(link, 'hysteria2');
    if (link.startsWith('hysteria://')) return parseURI(link, 'hysteria');
    if (link.startsWith('tuic://')) return parseURI(link, 'tuic');

    return { type: 'unknown', original: link };
}

function parseVmess(link) {
    try {
        const base64Part = link.replace('vmess://', '').split('#')[0];
        const jsonStr = Buffer.from(base64Part, 'base64').toString('utf-8');
        const config = JSON.parse(jsonStr);
        if (!config.add || !config.port) throw new Error('missing add/port');
        return {
            type: 'vmess',
            ps: config.ps || `${config.add}:${config.port}`,
            add: config.add,
            server: config.add,
            port: Number(config.port),
            id: config.id,
            original: link,
            config: config
        };
    } catch (e) {
        return { type: 'vmess', error: 'parse_error', original: link };
    }
}

/**
 * ss:// 三种写法都要兼容：
 *   1) ss://base64(method:password)@host:port#tag
 *   2) ss://base64(method:password@host:port)#tag
 *   3) ss://method:password@host:port#tag   （部分机场不编码）
 */
function parseSS(link) {
    try {
        let body = link.slice(5);
        let tag = '';

        const hashIdx = body.indexOf('#');
        if (hashIdx >= 0) {
            tag = safeDecode(body.slice(hashIdx + 1));
            body = body.slice(0, hashIdx);
        }
        const qIdx = body.indexOf('?');
        if (qIdx >= 0) body = body.slice(0, qIdx);

        let method, password, host, port;
        const atIdx = body.lastIndexOf('@');

        if (atIdx >= 0) {
            // 写法 1 / 3
            let userInfo = body.slice(0, atIdx);
            if (!userInfo.includes(':')) {
                userInfo = Buffer.from(userInfo, 'base64').toString('utf-8');
            }
            const sep = userInfo.indexOf(':');
            method = userInfo.slice(0, sep);
            password = userInfo.slice(sep + 1);

            const hostPort = body.slice(atIdx + 1);
            const colon = hostPort.lastIndexOf(':');
            host = hostPort.slice(0, colon);
            port = Number(hostPort.slice(colon + 1));
        } else {
            // 写法 2
            const decoded = Buffer.from(body, 'base64').toString('utf-8');
            const m = decoded.match(/^(.+?):(.+)@(.+):(\d+)$/);
            if (!m) throw new Error('bad ss payload');
            [, method, password, host] = m;
            port = Number(m[4]);
        }

        if (!host || !port || !method) throw new Error('bad ss');

        return {
            type: 'ss',
            ps: tag || `${host}:${port}`,
            add: host,
            server: host,
            port,
            method,
            password,
            original: link
        };
    } catch (e) {
        return { type: 'ss', error: 'parse_error', original: link };
    }
}

function parseSSR(link) {
    // SSR 链接是 ssr://base64(host:port:protocol:method:obfs:base64pass/?params)
    try {
        const decoded = Buffer.from(link.slice(6), 'base64').toString('utf-8');
        const [main, query = ''] = decoded.split('/?');
        const parts = main.split(':');
        if (parts.length < 6) throw new Error('bad ssr');
        const host = parts[0];
        const port = Number(parts[1]);
        const password = Buffer.from(parts[5], 'base64').toString('utf-8');
        const params = new URLSearchParams(query);
        const tag = params.get('remarks')
            ? Buffer.from(params.get('remarks'), 'base64').toString('utf-8')
            : `${host}:${port}`;
        if (!host || !port) throw new Error('bad ssr');
        return {
            type: 'ssr',
            ps: tag,
            add: host,
            server: host,
            port,
            method: parts[3],
            password,
            protocol: parts[2],
            obfs: parts[4],
            original: link
        };
    } catch (e) {
        return { type: 'ssr', error: 'parse_error', original: link };
    }
}

/**
 * vless / trojan / hysteria2 / tuic 这类标准 URI 格式统一解析
 */
function parseURI(link, type) {
    try {
        const u = new URL(link);
        const q = u.searchParams;
        const security = (q.get('security') || q.get('sni') ? 'tls' : '') || q.get('security') || '';
        const host = u.hostname;
        if (!host) throw new Error('missing host');

        const defaultPort = security ? 443 : (type === 'trojan' ? 443 : 80);
        const port = Number(u.port || defaultPort);

        return {
            type,
            ps: u.hash ? safeDecode(u.hash.slice(1)) : `${type}-${host}`,
            add: host,
            server: host,
            port,
            uuid: safeDecode(u.username || ''),
            password: safeDecode(u.username || ''),
            network: q.get('type') || 'tcp',
            tls: security === 'tls' || security === 'reality',
            sni: q.get('sni') || q.get('peer') || q.get('host') || host,
            path: q.get('path') || '/',
            host: q.get('host') || host,
            flow: q.get('flow') || '',
            original: link
        };
    } catch (e) {
        return { type, error: 'parse_error', original: link };
    }
}

function safeDecode(s) {
    try {
        return decodeURIComponent(s);
    } catch {
        return s;
    }
}

/**
 * 解析 Clash YAML 内容提取节点
 *
 * 修复点：原实现返回 { type:'clash_proxy', original: <对象> }，
 * 调用方把它塞进 string 集合后 parseNode 会 `link.startsWith is not a function`。
 * 现在直接转成内部统一格式（含 add/port/type），可被 validator 正常验证。
 *
 * @param {string} yamlContent
 * @returns {object[]} 内部格式节点列表
 */
export function parseClash(yamlContent) {
    if (typeof yamlContent !== 'string') return [];
    try {
        const doc = yaml.load(yamlContent);
        if (!doc || !Array.isArray(doc.proxies)) return [];
        return doc.proxies.map(clashProxyToNode).filter(Boolean);
    } catch (e) {
        console.error('Failed to parse YAML:', e.message);
        return [];
    }
}

function clashProxyToNode(p) {
    if (!p || typeof p !== 'object' || !p.server || !p.port) return null;

    const base = {
        add: p.server,
        server: p.server,
        port: Number(p.port),
        ps: p.name || `${p.type}-${p.server}`,
        clash: p
    };

    switch (p.type) {
        case 'vmess':
            return {
                ...base,
                type: 'vmess',
                id: p.uuid,
                config: {
                    aid: p.alterId ?? 0,
                    scy: p.cipher || 'auto',
                    net: p.network || 'tcp',
                    tls: p.tls ? 'tls' : '',
                    path: p['ws-opts']?.path || p['grpc-opts']?.['grpc-service-name'] || '/',
                    host: p['ws-opts']?.headers?.Host || p.server
                }
            };
        case 'ss':
            return { ...base, type: 'ss', method: p.cipher, password: p.password };
        case 'ssr':
            return { ...base, type: 'ssr', method: p.cipher, password: p.password, protocol: p.protocol, obfs: p.obfs };
        case 'vless':
            return {
                ...base,
                type: 'vless',
                uuid: p.uuid,
                network: p.network || 'tcp',
                tls: !!p.tls,
                sni: p.servername || p.sni || p.server,
                path: p['ws-opts']?.path || '/',
                host: p['ws-opts']?.headers?.Host || p.server,
                flow: p.flow || ''
            };
        case 'trojan':
            return {
                ...base,
                type: 'trojan',
                password: p.password,
                network: p.network || 'tcp',
                tls: true,
                sni: p.sni || p.server,
                path: p['ws-opts']?.path || '/',
                host: p['ws-opts']?.headers?.Host || p.server
            };
        case 'hysteria2':
        case 'hysteria':
            return { ...base, type: p.type, password: p.password, sni: p.sni || p.server };
        default:
            return null;
    }
}
