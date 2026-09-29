import config from './config.js';
import { crawlSources } from './crawler.js';
import { parseNode } from './parser.js';
import { validateNodes } from './validator.js';
import { probeNodes } from './probe.js';
import { saveResults, exportClash, exportSubscribe, saveRunLog } from './exporter.js';
import cron from 'node-cron';

const hasProbe = config.validator?.probe?.enabled !== false;

async function runTask() {
    const startTime = Date.now();
    const stats = {
        totalLinks: 0,
        validFormatNodes: 0,
        availableNodes: 0,
        failedNodes: 0,
        probedNodes: 0,
        probeFailedNodes: 0,
        probeFatal: null,
        errors: [],
        duration: 0
    };

    console.log(`\n[${new Date().toISOString()}] Starting task...`);
    try {
        // ---------- 1. 抓取 ----------
        const raw = await crawlSources();
        stats.totalLinks = raw.length;

        if (raw.length === 0) {
            console.log('No links found. Exiting task.');
            return;
        }

        // ---------- 2. 解析 ----------
        console.log('Parsing nodes...');
        const nodes = raw.map(item => {
            try {
                return parseNode(item);
            } catch (e) {
                return { type: 'unknown', error: e.message, original: item };
            }
        });

        // 去重：优先 server:port:type
        const seen = new Set();
        const validFormatNodes = nodes.filter(n => {
            if (!n || n.type === 'unknown' || n.error) return false;
            const key = `${n.type}|${n.add || n.server}|${n.port}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
        stats.validFormatNodes = validFormatNodes.length;
        console.log(`Parsed ${validFormatNodes.length} valid format nodes (from ${nodes.length} raw).`);

        if (validFormatNodes.length === 0) {
            console.log('No valid nodes after parsing. Exiting.');
            return;
        }

        // ---------- 2.5 保存未验证的全量 ----------
        console.log('Saving unvalidated nodes...');
        await exportClash(validFormatNodes, config.output.unvalidatedClashFileName);
        await exportSubscribe(validFormatNodes, config.output.unvalidatedSubscribeFileName);

        // ---------- 3. 第一层：TCP 粗筛（快速剔掉下线的）----------
        console.log('Layer 1/2: TCP reachability...');
        const { available: tcpAlive } = await validateNodes(validFormatNodes);
        stats.availableNodes = tcpAlive.length;

        // ---------- 3.5 第二层：mihomo 真实代理探测 ----------
        let finalNodes = tcpAlive;

        if (hasProbe) {
            console.log('Layer 2/2: real proxy probe via mihomo...');
            const { available: probed, failed: probeFailed, fatal } = await probeNodes(tcpAlive);

            if (fatal) {
                // 内核起不来 → 不能把节点全丢光，退回 TCP 结果并记录
                console.warn(`[probe] disabled this run: ${fatal}`);
                stats.probeFatal = fatal;
                stats.errors.push(`probe fatal: ${fatal}`);
            } else {
                stats.probedNodes = probed.length;
                stats.probeFailedNodes = probeFailed.length;
                finalNodes = probed;

                // 真实探测通过的单独出一份（比 TCP 版可信）
                if (config.output.probedClashFileName) {
                    await exportClash(probed, config.output.probedClashFileName);
                }

                // 把 TCP 通过但真实不可用的单独留档，便于分析假节点来源
                if (config.output.failedClashFileName) {
                    await exportClash(probeFailed, config.output.failedClashFileName);
                }
                if (config.output.failedSubscribeFileName) {
                    await exportSubscribe(probeFailed, config.output.failedSubscribeFileName);
                }
                stats.failedNodes = probeFailed.length;
            }
        } else {
            console.log('Probe disabled in config; using TCP results only.');
        }

        // ---------- 4. 保存最终可用节点 ----------
        console.log(`Saving ${finalNodes.length} validated nodes...`);
        await saveResults(finalNodes);

        console.log(
            `Task completed. raw=${stats.totalLinks} parsed=${stats.validFormatNodes} ` +
            `tcp=${stats.availableNodes} probed=${stats.probedNodes} ` +
            `probeFailed=${stats.probeFailedNodes}`
        );
    } catch (error) {
        console.error('Task failed:', error);
        stats.errors.push(error.stack || error.message);
    } finally {
        stats.duration = Date.now() - startTime;
        try {
            await saveRunLog(stats);
        } catch (e) {
            console.error('Failed to write run log:', e.message);
        }
    }
}

const args = process.argv.slice(2);

if (args.includes('--run-once')) {
    runTask().then(() => process.exit(0));
} else {
    console.log('Starting Node Crawler Service.');
    console.log(`Schedule: ${config.cronSchedule}`);
    console.log('Press Ctrl+C to exit.');

    runTask();
    cron.schedule(config.cronSchedule, () => runTask());
}
