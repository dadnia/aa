import config from './config.js';
import { crawlSources } from './crawler.js';
import { parseNode } from './parser.js';
import { validateNodes } from './validator.js';
import { saveResults, exportClash, exportSubscribe, saveRunLog } from './exporter.js';
import cron from 'node-cron';

async function runTask() {
    const startTime = Date.now();
    const stats = {
        totalLinks: 0,
        validFormatNodes: 0,
        availableNodes: 0,
        failedNodes: 0,
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

        // ---------- 3. 验证 ----------
        const { available, failed } = await validateNodes(validFormatNodes);
        stats.availableNodes = available.length;
        stats.failedNodes = failed.length;

        // ---------- 3.5 保存验证失败的（用于区分「没抓到」和「抓到了但不通」）----------
        if (config.output.failedClashFileName) {
            await exportClash(failed, config.output.failedClashFileName);
        }
        if (config.output.failedSubscribeFileName) {
            await exportSubscribe(failed, config.output.failedSubscribeFileName);
        }

        // ---------- 4. 保存可用节点 ----------
        console.log('Saving validated nodes...');
        await saveResults(available);

        console.log(
            `Task completed. raw=${stats.totalLinks} parsed=${stats.validFormatNodes} ` +
            `available=${stats.availableNodes} failed=${stats.failedNodes}`
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
