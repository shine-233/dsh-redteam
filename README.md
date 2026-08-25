# dsh-redteam — DSH 红队/渗透测试模式

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（dsh）的红队 engagement 模式：在授权范围内记录目标与授权、拆解意图、留证事实、确认漏洞与资产，并在 Web 中以链路图、漏洞和资产视图实时展示。二次开发自 [howmp/dsh-pentest](https://github.com/howmp/dsh-pentest)，在其基础上新增证据链与跨会话历史。

本目录是自包含 bundle 包（`dsh-redteam`）：宿主插件、Web 界面和 sqlite 后端通过包内 `exports` 一同分发，单个 tarball 即可安装。

## 安装

### 从 Release 安装

```sh
dsh plugin --profile web add https://github.com/shine-233/dsh-redteam/releases/latest/download/dsh-redteam.tar.gz
```

### 从本地文件安装

```sh
dsh plugin --profile web add file:C:\path\to\dsh-redteam-0.3.0.tgz
```

重启 dsh 后，在新会话中选择自动注册的「红队模式」预设。

## 与上游（dsh-pentest）的差异

| 能力 | dsh-pentest | dsh-redteam |
| --- | --- | --- |
| 证据链 | 无 | `redteam_add_evidence`（command / output / screenshot / file / url），fact 通过 `evidenceIds` 引用 |
| 跨会话历史 | 单会话作用域，无续跑 | `redteam_engagements` 列出全部历史；新 goal 关闭旧 engagement 但不删除任何记录 |
| 报告格式 | Markdown 渲染 | Markdown（人读）/ JSON（程序消费）双格式，含时间线与严重度分布 |
| 协议语言 | 中文 | `language: 'zh' \| 'en'` 双语配置 |
| 边存储 | edges 表显式存边 | 边从引用（intent.goalId / fact.intentId / finding.intentId / asset.parentId）读取时派生，记录不可能悬空 |
| CVSS 定级 | 无 | finding 给 `cvssVector`（CVSS v3.1 基础向量）即按 FIRST 规范自动计算分值 |
| MITRE ATT&CK | 无 | finding 可映射 `techniqueIds`（如 T1110.003），写入时校验格式 |
| Kill-chain 阶段 | 无 | intent / fact 可标 phase（recon / enumeration / exploitation / post-exploitation / reporting） |
| 凭据追踪 | 无 | `redteam_add_credential` 登记口令/哈希/API key/token，Web 视图与报告自动脱敏，明文只进本地库；`redteam_update_credential` 验证后更新 valid/invalid 并留证 |
| 任务树生命周期 | 无（PentestGPT PTT 风格） | intent 有 active/done/blocked 状态，`redteam_update_intent` 推进；UI 进度板与报告进度行 |
| 漏洞复测闭环 | 无（Strix find-and-fix 风格） | `redteam_retest_finding` 记录 fixed/still-vulnerable 复测结果，报告标注 ✅ 已修复与复测时间 |
| OWASP Top 10 | 无 | finding 可映射 `owaspIds`（如 A01:2021 / A05:2017），写入时校验格式 |
| 资产指纹标签 | 无 | asset 可挂 tags（服务名/组件/版本），资产表与报告展示 |
| 资产锚点与覆盖度 | 无（ARTEX 双图架构风格） | intent 用 `assetIds` 锚定目标资产，`redteam_state` / 报告 / 资产视图输出已测 vs 未测覆盖 |
| fact→intent 派生边 | derived_from 边 | intent 用 `derivedFrom` 引用触发它的事实，血缘链入图 |
| 多步攻击链依赖 | 无（ARTEX planner todolist 风格） | intent 用 `dependsOn` 声明前置步骤（注入→取凭据→横向→提权），图中虚线呈现 |
| 目标显式结论 | 无（ARTEX prove_goal 风格） | `redteam_close_goal` 以 achieved/partial/not-achieved 收尾并留摘要，报告头部与历史列表引用；**收尾后报告/状态/图仍可完整读取** |
| SARIF 导出 | 无 | `redteam_report format=sarif` 输出 SARIF 2.1.0（GitHub/GitLab code scanning 可直接摄取），CVSS 映射 security-severity，ATT&CK/OWASP 作为 tags |
| 产物追踪 | Artifact 实体（PentAGI ER 模型） | `redteam_add_artifact` 登记 engagement 的交付物（战利品/截图/日志/exp 脚本/转储），与 evidence 区分：产物是输出，证据支撑论断；Web 产物标签页 + 报告产物表 |
| 提交事务性 | 无对照 | `redteam_submit` 两阶段提交——批内任何校验失败零残留，子代理重试不会产生重复记录 |
| 收尾后可读 | 无对照 | `redteam_close_goal` 之后 state/graph/report 仍完整可读（最终报告工作流） |
| 人工转向黑板 | Hint 原语（Cairn 黑板架构） | `redteam_add_hint` 把用户/客户/操作者的方向性指令原文入档（user/operator/client 来源标注），Web 头部指示条 + 报告「人工转向」段 |
| 漏洞去重标记 | issue dedup（Dradis 类平台） | `redteam_add_finding duplicateOf` 标记重复漏洞（子代理双报场景），报告标注 dup of |
| 检测状态追踪 | VECTR 红/蓝对抗度量 | finding/retest 记录蓝队反馈 undetected/logged/alerted/prevented，报告输出防御触达率 |
| ATT&CK 技术覆盖 | VECTR/Navigator 覆盖矩阵 | intent 标计划技术、finding 证实用技术，state/报告输出 proven vs attempted-only 覆盖摘要 |
| CWE 弱点映射 | PwnDoc 漏洞库标配 | finding 可挂 `cweIds`（CWE-79 格式），写入校验，SARIF tags 携带 |
| 样本登记 | 恶意软件分析报告惯例 | `redteam_add_sample` 以 sha256（64 hex 强制）为保管链锚点登记二进制/文档/内存转储，附 md5/sha1/格式/架构 |
| IOC 追踪 | MISP/Cuckoo 提取工作流 | `redteam_add_ioc` 按 ip/domain/url/hash/mutex/registry/filepath/user-agent 分类记录指标，可挂样本与意图，报告输出 IOC 附录表 |

## 架构速览

- **领域模型**（`src/spec.ts`）：storage domain `redteam`（version 1，增量演进兼容旧库）——`goals` / `intents` / `facts` / `assets` / `findings` / `evidence` / `credentials` 七张表。goal 按会话键控，其余记录 id 为 `<kind>-<n>`（按会话计数，重开 goal 归零）。
- **确定性 id**（`src/store.ts`）：工具返回 id 供模型跨调用引用；会话投影从日志纯重放同一张图。
- **工具**（`src/tools.ts`）：15 个 —— `redteam_add_goal`（authorization 必填，重开 goal 关闭旧 engagement）/ `redteam_add_intent`（可选 phase）/ `redteam_add_evidence` / `redteam_add_fact`（evidenceIds 引用、可选 phase）/ `redteam_add_asset`（parentId 留空为根资产，tags 指纹）/ `redteam_add_finding`（reproducibleSteps 必填；cvssVector 自动算分；techniqueIds/owaspIds 校验）/ `redteam_add_credential`（凭据登记，脱敏展示）/ `redteam_update_intent`（任务树状态推进）/ `redteam_retest_finding`（复测闭环）/ `redteam_update_credential`(验证凭据) / `redteam_submit`（子 agent 分批直写指定父 intent）/ `redteam_state` / `redteam_graph` / `redteam_report`（markdown|json）/ `redteam_engagements`（历史列表）。
- **CVSS 计算**（`src/cvss.ts`）：FIRST CVSS v3.1 基础分实现（含官方 roundup 防浮点漂移），20 个参考向量测试覆盖。
- **会话投影**（`src/projection.ts`）：折叠已日志化的 `redteam_*` 调用为 `{ goal, nodes, assets, findings, credentials, counts }`，镜像 store 的引用拒绝；密文永不进入投影。
- **Web 标签页**（`src/client/`）：按会话注册（当前会话或祖先链含 redteam 预设即显示）；五个子标签——探索链路（关系图）、漏洞（严重度/CVSS 分值/ATT&CK 技术标签）、资产、凭据（脱敏列表）、报告（Markdown 渲染、复制与保存）。
- **协议**（`src/instructions.ts`）：系统提示词段 `redteam:protocol`（order 50），双语逐字撰写而非运行时翻译；要求授权留痕、事实必留证、漏洞必可复现、凭据不落明文。

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
