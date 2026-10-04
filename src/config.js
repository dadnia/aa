// ============================================================
// 全局测速链接（唯一真源）
//   每个节点都必须通过它完成一次真实 HTTP 访问才算「可用」：
//     - mihomo 内核探测：走代理 GET <testUrl>，拿真实往返延迟
//     - 导出的 Clash 配置：url-test 组也用它做健康检查
//   改这一处即全局生效；也可用环境变量 TEST_URL 覆盖（CI 里由 workflow 注入）。
// ============================================================
export const TEST_URL = process.env.TEST_URL || 'https://www.gstatic.com/generate_204';

export default {
    // 测速链接：所有节点访问的靶点
    testUrl: TEST_URL,

    // ============================================================
    // 目标订阅源或网页列表
    //   支持三种形态：
    //   1) 订阅链接   https://xxx/api/v1/client/subscribe?token=...
    //   2) 单节点 URI vmess:// vless:// ss:// trojan:// hysteria2://
    //   3) 网页/raw   https://raw.githubusercontent.com/.../xxx.txt
    //
    //   ⚠ 通配符源（含 *）会由 Crawlee 展开，单条就能吃满
    //     maxRequestsPerCrawl 配额，源多时建议注释掉或调大配额。
    // ============================================================
    sources: [
        // --- 直连订阅 / raw 文件（成功率最高，建议优先放这里）---
        // 'https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2',
        // 'https://你的机场域名/api/v1/client/subscribe?token=TOKEN_A',

        // --- 网页抓取（依赖页面结构，改版即失效）---
        'https://oneclash.cc/a/2312.html',
        'https://clashnodev2ray.github.io/',
        'https://clashnodev2ray.github.io/2025/12/12/free-ssr-node/',
        'https://freenode.openrunner.net/tag/v2ray/',
        'https://freenode.openrunner.net/post/20251212/',
        'https://www.cfmem.com/search/label/free',
        'https://clashgithub.com/category/freenode',

        // --- GitHub 仓库页：默认只能拿到 README，节点在 raw 文件里 ---
        //     程序会自动把 /blob/<branch>/<path> 改写成 raw 地址，
        //     但仓库根 URL 只能靠页面内链接发现，成功率低。
        'https://github.com/free-nodes/v2rayfree',
        'https://github.com/free-nodes/clashfree',
        'https://github.com/free18/v2ray',
        'https://github.com/Pawdroid/Free-servers',
        'https://github.com/John19187/v2ray-SSR-Clash-Verge-Shadowrocke',
        'https://github.com/Alvin9999/new-pac/wiki/v2ray%E5%85%8D%E8%B4%B9%E8%B4%A6%E5%8F%B7',
        'https://github.com/shaoyouvip/free',
        'https://github.com/hwanz/SSR-V2ray-Trojan-vpn',
        'https://github.com/chengaopan/AutoMergePublicNodes',
        'https://github.com/awesome-vpn/awesome-vpn',
        'https://github.com/Jsnzkpg/Jsnzkpg',
        'https://github.com/peasoft/NoMoreWalls',
        'https://github.com/dongyubin/Free-AppleId-Serve',

        // --- 通配符：默认关闭，需要时打开并把 maxRequestsPerCrawl 调大 ---
        // 'https://oneclash.cc/a/*.html',
    ],

    // 抓取设置
    crawler: {
        // 通配符源会大量占用配额；有通配符时建议 >= 200
        maxRequestsPerCrawl: 200,
        requestTimeoutSecs: 15,
        maxDepth: 1, // 1=只爬当前页；2=当前页+它包含的链接（配额翻倍）
        userAgent: 'clash-verge/v2.0.0', // 很多机场只对该 UA 返回内容
        concurrentRequests: 5,
    },

    // 验证设置
    validator: {
        // ---- 第 1 层：TCP 粗筛（快速剔掉已下线的，不经过测速链接）----
        timeout: 5000,  // TCP ping 超时(ms)；3000 对海外节点偏短，误杀严重
        attempts: 2,    // 重试次数
        concurrent: 20, // 并发验证数量
        maxDelay: 800,  // TCP RTT 超过该值视为不可用(ms)；与测速链接阈值口径一致

        // ---- 第 2 层：真实可用性探测（mihomo 内核 + 测速链接）----
        // TCP ping 只能筛掉"服务器已下线"，筛不掉"参数失效"。
        // Cloudflare IP / *.workers.dev 对任何端口都接受 TCP，必然假通过。
        // 开启 probe 后会拉起 mihomo，走真实代理请求访问 testUrl 拿延迟，
        // 延迟高于 maxDelayMs 的节点在这一层被直接剔除。
        probe: {
            enabled: true,
            bin: './bin/mihomo',      // 内核路径（相对项目根）；CI 里由 workflow 下载
            apiPort: 9090,            // external-controller 端口
            mixedPort: 7899,          // 混合代理端口（探测本身不用，但内核需要）
            timeoutMs: 5000,          // 单节点探测超时；超时即判失败
            concurrency: 32,          // 并发探测数
            testUrl: TEST_URL,        // ← 测速链接（与全局唯一真源一致）
            maxDelayMs: 800,          // ← 经测速链接实测延迟超过该值直接去除(ms)
            workDir: '.probe',        // 运行时目录
            startupTimeoutMs: 60000,  // 内核启动等待上限
        },
    },

    // 输出设置
    //   所有相对路径都相对【项目根目录】解析（不再依赖 cwd）
    output: {
        dir: './output',
        // 通过验证的节点
        clashFileName: 'clash.yaml',
        subscribeFileName: 'subscribe.txt',
        // 未验证的全部节点（仅格式合法）
        unvalidatedClashFileName: 'clash_all.yaml',
        unvalidatedSubscribeFileName: 'subscribe_all.txt',
        // 验证失败的节点（新增：用于区分「没抓到」和「抓到了但不通」）
        failedClashFileName: 'clash_failed.yaml',
        failedSubscribeFileName: 'subscribe_failed.txt',
        // 真实探测通过的节点（由 mihomo 实测，比 clash.yaml 可信）
        probedClashFileName: 'clash_probed.yaml',
        // 日志目录；留空则自动使用 <dir>/logs
        logDir: '',
    },

    // 定时任务 (Cron 表达式) - 默认每4小时运行一次
    cronSchedule: '0 */4 * * *'
};
