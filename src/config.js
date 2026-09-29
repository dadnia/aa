export default {
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
        timeout: 5000,  // TCP ping 超时(ms)；3000 对海外节点偏短，误杀严重
        attempts: 2,    // 重试次数
        concurrent: 20, // 并发验证数量
        maxDelay: 3000, // 延迟超过该值视为不可用(ms)
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
        // 日志目录；留空则自动使用 <dir>/logs
        logDir: '',
    },

    // 定时任务 (Cron 表达式) - 默认每4小时运行一次
    cronSchedule: '0 */4 * * *'
};
