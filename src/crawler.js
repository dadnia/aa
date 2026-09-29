import { CheerioCrawler, Configuration } from 'crawlee';
import config from './config.js';
import { decodeSubscription, extractLinks, parseClash } from './parser.js';
import axios from 'axios';

const UA = config.crawler.userAgent || 'clash-verge/v2.0.0';

/** 统一的 axios 请求头：很多机场只对 Clash 系 UA 返回内容 */
function reqHeaders(extra = {}) {
    return {
        'User-Agent': UA,
        Accept: '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        ...extra
    };
}

/**
 * GitHub 页面 URL → raw 地址
 *   https://github.com/o/r/blob/main/a/b.txt  →  https://raw.githubusercontent.com/o/r/main/a/b.txt
 */
export function toRawUrl(url) {
    const m = url.match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/(?:blob|raw)\/([^/]+)\/(.+)$/);
    if (m) return `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}/${m[4]}`;
    return url;
}

/** 绝对化相对链接 */
function absolutize(href, base) {
    try {
        return new URL(href, base).toString();
    } catch {
        return null;
    }
}

/** 判断是否像订阅文件 */
export function looksLikeSubscription(url) {
    return /\.(txt|yaml|yml|json|conf|list|base64|sub)(\?|$)/i.test(url);
}

/**
 * 从一段文本里抽取节点（明文优先，再试 base64，最后试 Clash YAML）
 * 修复点：原实现把 decodeSubscription 放在前面且判断 `links.length > 0`，
 * 由于它恒返回非空数组，明文订阅永远走不到 extractLinks，还会灌入乱码。
 *
 * @param {string} content
 * @param {Set} sink
 */
function harvest(content, sink) {
    if (typeof content !== 'string' || content.length === 0) return;

    // 1) 明文 URI
    const plain = extractLinks(content);
    plain.forEach(l => sink.add(l));

    // 2) base64 订阅（内部已做协议校验，失败返回 []）
    if (plain.length === 0) {
        decodeSubscription(content).forEach(l => {
            if (typeof l === 'string') sink.add(l);
        });
    }

    // 3) Clash YAML → 内部统一对象（parseNode 可直接接受对象）
    if (/^\s*(proxies|proxy-providers)\s*:/m.test(content) || /^\s*port\s*:/m.test(content)) {
        parseClash(content).forEach(n => sink.add(n));
    }
}

/**
 * 抓取所有源并返回提取到的节点
 * @returns {Promise<Array<string|object>>} 原始链接字符串 + Clash 对象节点
 */
export async function crawlSources() {
    const found = new Set();

    const directUrls = [];
    const pageUrls = [];
    const globs = [];

    config.sources.forEach(url => {
        if (typeof url !== 'string' || !url.trim()) return;
        const u = url.trim();

        if (u.includes('*')) {
            globs.push(u);
            const baseUrl = u.substring(0, u.indexOf('*'));
            const startUrl = baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
            console.log(`Wildcard source: ${u} -> start at ${startUrl}`);
            pageUrls.push(startUrl);
        } else if (
            u.includes('subscribe') || u.includes('feed') || u.includes('token=') ||
            looksLikeSubscription(u) || u.startsWith('vmess://') || u.startsWith('vless://') ||
            u.startsWith('ss://') || u.startsWith('trojan://')
        ) {
            directUrls.push(u);
        } else {
            pageUrls.push(u);
        }
    });

    console.log(`Starting crawl. Direct: ${directUrls.length}, Pages: ${pageUrls.length}, Globs: ${globs.length}`);

    // ---------- 1. 直连订阅 / 单节点 ----------
    for (const url of directUrls) {
        // 直接就是节点 URI，无需请求
        if (/^(vmess|vless|ss|ssr|trojan|hysteria2?|hy2|tuic):\/\//i.test(url)) {
            found.add(url);
            continue;
        }

        try {
            console.log(`Fetching subscription: ${url}`);
            const res = await axios.get(toRawUrl(url), {
                timeout: (config.crawler.requestTimeoutSecs || 15) * 1000,
                headers: reqHeaders(),
                maxRedirects: 5,
                responseType: 'text',
                transformResponse: [d => d]   // 禁止 axios 自动 JSON.parse
            });
            harvest(res.data, found);
        } catch (error) {
            console.error(`Failed to fetch ${url}: ${error.message}`);
        }
    }

    // ---------- 2. 网页抓取 ----------
    if (pageUrls.length > 0) {
        let crawlerOptions = {
            maxRequestsPerCrawl: config.crawler.maxRequestsPerCrawl || 200,
            maxConcurrency: config.crawler.concurrentRequests || 5,
            requestHandlerTimeoutSecs: (config.crawler.requestTimeoutSecs || 15) * 2,
            navigationTimeoutSecs: (config.crawler.requestTimeoutSecs || 15) * 1000,
            preNavigationHooks: [
                ({ request }, gotOptions) => {
                    gotOptions.headers = { ...(gotOptions.headers || {}), ...reqHeaders() };
                    request.headers = { ...(request.headers || {}), ...reqHeaders() };
                }
            ],
            requestHandler: async ({ $, request, enqueueLinks, log }) => {
                const depth = request.userData?.depth || 1;
                console.log(`Scanning page [d${depth}]: ${request.url}`);

                const text = $('body').text();
                harvest(text, found);
                harvest($.html(), found);

                // 收集疑似订阅链接
                const subLinks = new Set();

                $('a[href]').each((i, el) => {
                    const href = $(el).attr('href');
                    if (!href) return;
                    const abs = absolutize(href, request.url);
                    if (!abs) return;
                    // GitHub blob → raw
                    if (/^https?:\/\/github\.com\/[^/]+\/[^/]+\/(blob|raw)\//.test(abs)) {
                        subLinks.add(toRawUrl(abs));
                    } else if (looksLikeSubscription(abs)) {
                        subLinks.add(abs);
                    }
                });

                // 正文里裸露的 URL
                const urlRe = /https?:\/\/[^\s"'<>)]+\.(?:txt|yaml|yml|json|conf)(?:\?[^\s"'<>)]*)?/gi;
                (text.match(urlRe) || []).forEach(m => subLinks.add(m));
                ($.html().match(urlRe) || []).forEach(m => subLinks.add(m));

                console.log(`  found ${subLinks.size} candidate sub-links`);

                for (const subLink of subLinks) {
                    try {
                        const res = await axios.get(subLink, {
                            timeout: (config.crawler.requestTimeoutSecs || 15) * 1000,
                            headers: reqHeaders({ Referer: request.url }),
                            maxRedirects: 5,
                            responseType: 'text',
                            transformResponse: [d => d]
                        });
                        harvest(res.data, found);
                    } catch (err) {
                        console.error(`  failed sub-link ${subLink}: ${err.message}`);
                    }
                }

                // 深度控制
                if (depth >= (config.crawler.maxDepth || 1)) return;

                // 通配符入队
                if (globs.length > 0) {
                    await enqueueLinks({
                        globs: globs,
                        baseUrl: request.url,
                        label: 'wildcard-match',
                        userData: { depth: depth + 1 }
                    });
                }
            }
        };

        let crawler;
        try {
            // persistStorage: false → 不落 storage/ 目录，避免仓库被状态文件撑爆
            crawler = new CheerioCrawler(crawlerOptions, new Configuration({ persistStorage: false }));
        } catch (e) {
            console.warn(`Falling back to default Configuration: ${e.message}`);
            crawler = new CheerioCrawler(crawlerOptions);
        }

        await crawler.run(pageUrls);
    }

    console.log(`Crawl finished. Found ${found.size} unique nodes.`);
    return Array.from(found);
}
