import tcpping from 'tcp-ping';
import config from './config.js';

/**
 * 验证单个节点（TCP 连通性 + 延迟）
 *
 * 修复点：
 *  - 统一从 node.add || node.server 取地址，兼容 ss/vless/trojan 解析结果
 *  - 原实现只认 node.add，ss/vless 恒被判失败
 *
 * @param {object} node
 * @returns {Promise<object>} node.delay 为 -1 表示不可用
 */
export function pingNode(node) {
    return new Promise((resolve) => {
        const host = node?.add || node?.server;
        const port = Number(node?.port);

        if (!host || !port || !Number.isInteger(port) || port <= 0 || port > 65535) {
            if (node) node.delay = -1;
            return resolve(node);
        }

        let settled = false;
        const done = (delay) => {
            if (settled) return;
            settled = true;
            node.delay = delay;
            resolve(node);
        };

        // 兜底超时：tcp-ping 在极端情况下可能不回调
        const guard = setTimeout(
            () => done(-1),
            config.validator.timeout * (config.validator.attempts + 1) + 1000
        );

        try {
            tcpping.ping({
                address: host,
                port,
                attempts: config.validator.attempts,
                timeout: config.validator.timeout
            }, (err, data) => {
                clearTimeout(guard);
                if (err || !data || isNaN(data.avg)) {
                    done(-1);
                } else {
                    done(Math.round(data.avg));
                }
            });
        } catch (e) {
            clearTimeout(guard);
            done(-1);
        }
    });
}

/**
 * 批量验证节点
 *
 * @param {object[]} nodes
 * @returns {Promise<{available: object[], failed: object[]}>}
 */
export async function validateNodes(nodes) {
    console.log(`Starting validation for ${nodes.length} nodes...`);
    const results = [];
    const concurrency = Math.max(1, config.validator.concurrent || 20);
    const maxDelay = config.validator.maxDelay ?? 3000;

    for (let i = 0; i < nodes.length; i += concurrency) {
        const chunk = nodes.slice(i, i + concurrency);
        const chunkResults = await Promise.all(chunk.map(node => pingNode(node)));
        results.push(...chunkResults);

        const done = Math.min(i + concurrency, nodes.length);
        if (done % (concurrency * 5) === 0 || done === nodes.length) {
            console.log(`  validated ${done}/${nodes.length}`);
        }
    }

    const available = results.filter(n => n && n.delay > 0 && n.delay < maxDelay);
    const failed = results.filter(n => !n || !(n.delay > 0) || n.delay >= maxDelay);

    console.log(`Validation complete. ${available.length}/${nodes.length} available, ${failed.length} failed.`);
    return { available, failed };
}

/**
 * 向后兼容：只返回可用节点的旧签名
 * @param {object[]} nodes
 * @returns {Promise<object[]>}
 */
export async function validateNodesLegacy(nodes) {
    const { available } = await validateNodes(nodes);
    return available;
}
