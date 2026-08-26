# Changelog

所有显著变更记录在本文件。格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本遵循语义化。

## [1.6.0] — 2026-08-26

对标 DefectDojo 分诊工作流与度量面板的成熟度迭代。

### 新增
- **分诊状态**：`redteam_flag_finding` 为漏洞应用 `under-review | false-positive | out-of-scope | risk-accepted`（含说明与证据引用），`none` 清除；标记不删除记录——报告/markdown·HTML 徽章标注，**SARIF 对误报输出 suppressions（justification 携带）**
- **跨表搜索**：`redteam_search` 覆盖意图/事实/资产/漏洞/凭据(脱敏)/产物/样本/IOC/目标/hint/scope/证据标签 12 类记录；原始密文不可检索
- **全局度量**：`redteam_overview` 跨全部 engagement 聚合（表计数、严重度分布、检测反馈、分诊状态、修复数）——DefectDojo metrics-dashboard 风格
- 投影 finding 携带 `flag`，Web 漏洞卡片显示分诊徽章
- 子代理围栏新增 `redteam_flag_finding`

## [1.5.0] — 2026-08-26

### 新增
- 事实与证据入投影：facts（detail 截断 240 字符/phase/confidence/evidenceIds）与 evidence 元数据（kind/label）；**证据捕获内容永不进入 Web 投影**
- 链路图事实节点显示真实详情，点选抽屉展示阶段/置信度/证据引用
- 新增「证据」子标签（元数据表 + 事实清单）——13 张表全部具备可视化入口

## [1.4.0] — 2026-08-26

### 新增
- VECTR 检测反馈入 Web：投影 finding 携带 detected/duplicateOf；漏洞卡片 🫥📝🔔⛔ 徽章与重复标记；统计页防御触达率面板

### 工程
- GitHub Actions CI：push/PR 全量验证；`v*` tag 自动构建并挂 tarball 到 Release

## [1.3.0] — 2026-08-26

### 变更
- 协议提示词接入范围注册表工作流（开场第 2 步登记 in/out 边界；边界调整走 hint+scope 双通道；报告格式全清单），中英双语同步

## [1.2.0] — 2026-08-26

### 新增
- **范围结构化注册表**：`redteam_add_scope kind=in/out`（第 13 张表 scope_entries，共享匹配器 `src/scope.ts`）；资产/漏洞/IOC 自动判定越界与漏登，state/统计面板/全部报告输出合规表
- **IOC CSV 导出**（format=ioc-csv）与 **TAXII 2.1 信封导出**（format=taxii）
- **自包含 HTML 报告**（format=html）：深色主题内联 CSS、严重度条形、范围合规表、证据折叠附录

## [1.1.0] — 2026-08-26

### 新增
- ATT&CK Navigator 层导出（format=navlayer v4.5：证实 100 分绿 / 尝试 50 分琥珀）
- STIX 2.1 bundle 导出（vulnerability + indicator 标准 pattern）
- 凭据复用分析与 nextSteps 启发式建议（state + 执行摘要）
- client 纳入类型检查、ResizeObserver 守卫、jsdom 冒烟测试

## [1.0.0]

- 目标核对单（redteam_add_objective/prove_objective，CTFd/Cairn 模型）、CVE 引用；工具 22 个、表 12 张

## [0.9.0]

- 样本登记（sha256 保管链，第 10 张表）与 IOC 追踪（第 11 张表）

## [0.8.0]

- VECTR 式检测状态追踪、ATT&CK 技术覆盖摘要、CWE 映射

## [0.7.0]

- Hint 人工转向黑板原语（Cairn）、finding duplicateOf 去重标记（Dradis 类平台）

## [0.6.0]

- Artifact 产物追踪（PentAGI ER 模型）、产物标签页、报告产物表与时间线

## [0.5.0]

- submit 两阶段事务化、closeGoal 后报告/状态可读、SARIF 2.1.0 导出、子代理围栏补齐

## [0.4.0]

- 资产锚点与覆盖度、derived_from 派生边、多步链依赖、redteam_close_goal 显式结论（ARTEX 双图架构）

## [0.3.0]

- 任务树生命周期、漏洞复测闭环、凭据验证流转、OWASP Top 10 映射、资产指纹标签

## [0.2.0]

- CVSS v3.1 自动定级、MITRE ATT&CK 映射、kill-chain 阶段、凭据追踪（脱敏）、报告时间线

## [0.1.0]

- 首个版本：DSH 红队/渗透测试模式 bundle（二次开发自 howmp/dsh-pentest）
