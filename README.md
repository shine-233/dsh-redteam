# dsh-redteam — DSH 红队/渗透测试模式

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（dsh）的红队 engagement 模式：在授权范围内记录目标与授权、拆解意图、留证事实、确认漏洞与资产，并在 Web 中以链路图、漏洞和资产视图实时展示。二次开发自 [howmp/dsh-pentest](https://github.com/howmp/dsh-pentest)，在其基础上新增证据链与跨会话历史。

本目录是自包含 bundle 包（`dsh-redteam`）：宿主插件、Web 界面和 sqlite 后端通过包内 `exports` 一同分发，单个 tarball 即可安装。

## 安装

### 从本地文件安装

```sh
dsh plugin --profile web add file:C:\path\to\dsh-redteam-0.1.0.tgz
```

重启 dsh 后，在新会话中选择自动注册的「红队模式」预设。

## 与上游（dsh-pentest）的差异

| 能力 | dsh-pentest | dsh-redteam |
| --- | --- | --- |
| 证据链 | 无 | `redteam_add_evidence`（command / output / screenshot / file / url），fact 通过 `evidenceIds` 引用 |
| 跨会话历史 | 单会话作用域，无续跑 | `redteam_engagements` 列出全部历史；新 goal 关闭旧 engagement 但不删除任何记录 |
| 报告格式 | Markdown 渲染 | Markdown（人读）/ JSON（程序消费）双格式 |
| 协议语言 | 中文 | `language: 'zh' \| 'en'` 双语配置 |
| 边存储 | edges 表显式存边 | 边从引用（intent.goalId / fact.intentId / finding.intentId / asset.parentId）读取时派生，记录不可能悬空 |

## 架构速览

- **领域模型**（`src/spec.ts`）：storage domain `redteam`（version 1）——`goals` / `intents` / `facts` / `assets` / `findings` / `evidence` 六张表。goal 按会话键控，其余记录 id 为 `<kind>-<n>`（按会话计数，重开 goal 归零）。
- **确定性 id**（`src/store.ts`）：工具返回 id 供模型跨调用引用；会话投影从日志纯重放同一张图。
- **工具**（`src/tools.ts`）：11 个 —— `redteam_add_goal`（authorization 必填，重开 goal 关闭旧 engagement）/ `redteam_add_intent` / `redteam_add_evidence` / `redteam_add_fact`（evidenceIds 引用）/ `redteam_add_asset`（parentId 留空为根资产）/ `redteam_add_finding`(reproducibleSteps 必填至少一步) / `redteam_submit`（子 agent 分批直写指定父 intent，批内先 evidence 后 facts/findings）/ `redteam_state` / `redteam_graph` / `redteam_report`（markdown|json）/ `redteam_engagements`（历史列表）。
- **会话投影**（`src/projection.ts`）：折叠已日志化的 `redteam_*` 调用为 `{ goal, nodes, assets, counts }`，镜像 store 的引用拒绝。
- **Web 标签页**（`src/client/`）：按会话注册（当前会话或祖先链含 redteam 预设即显示）；四个子标签——探索链路（关系图）、漏洞（严重度/复现步骤/影响资产）、资产、报告（Markdown 渲染、复制与保存）。
- **协议**（`src/instructions.ts`）：系统提示词段 `redteam:protocol`（order 50），双语逐字撰写而非运行时翻译；要求授权留痕、事实必留证、漏洞必可复现。

## 已知边界

- **数据库**：红队记录写入 `$DSH_HOME/storages/redteam.db`（sqlite，经 bundle 补丁路由）。宿主其它域的存储不受影响（仍为宿主默认 json 后端）。
- **授权**：只测试有授权的目标。`authorization` 是必填审计事实（授权对象/书面许可引用），写入状态与最终报告留痕；它不是门禁——扫描/利用动作仍受部署沙箱与审批约束。
- **Web 图为窗口视图**：投影有节点上限，超出后最旧被逐出；完整记录以 `redteam_state` / `redteam_report`（读存储层）为准。
- **运行时要求**：sqlite 后端使用 Node.js `node:sqlite`，需 Node.js >= 22.5（engines: `^22.19.0 || >=24.0.0`）。

## 开发

```sh
pnpm install
pnpm build        # tsdown 构建到 lib/
pnpm typecheck    # tsc --noEmit
pnpm test         # vitest run
pnpm pack:bundle  # npm pack 出可安装 tarball
```

目录结构：

```
dsh-redteam/
├── package.json               # bundle manifest：exports 子路径 + dsh.bundle.patch + dsh.client
├── cordis.patch.yml           # 补丁层：UI、sqlite 后端、storage-domain 路由、preset root
├── src/                       # 源码
│   ├── plugin.ts              #   宿主插件装配（tools + protocol + projection）
│   ├── spec.ts / store.ts     #   领域模型与 engagement 存储
│   ├── tools.ts               #   11 个 redteam_* 工具
│   ├── projection.ts          #   会话投影定义
│   ├── instructions.ts        #   双语协议提示词段
│   ├── client/                #   浏览器半：RedteamView / ChainGraph / FindingsView / AssetsView / ReportView
│   └── storage-sqlite/        #   sqlite 后端（node:sqlite）
├── preset/redteam/            # 「红队模式」agent 预设（bundle 自动注册）
├── lib/                       # 构建产物（npm pack 内容）
└── tests/                     # vitest：bundle / store / tools / projection
```

## 参考项目

- [howmp/dsh-pentest](https://github.com/howmp/dsh-pentest) — 本项目的前身与基础
- [ARTEX](https://github.com/Autumn-27/ARTEX)

## License

MIT
