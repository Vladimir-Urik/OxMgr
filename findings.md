# 发现与决策

## 需求
用户希望基于 `github.com/Vladimir-Urik/OxMgr` Fork 新建 `slim` 分支，并计划：
1. 移除 `oxmgr deploy` 及 hook 相关功能。
2. 移除 Web API 相关功能。
3. `oxfile` 中 `max_restarts = -1` 时允许服务无限次尝试重启。
4. `oxfile` 中 `crash_restart_limit` 默认值改为 0。
5. 修复已启动目标服务的 oxfile 配置使用 `./` 相对日志路径时，日志应写入服务配置 `cwd` 下。
6. 新建 Build Action，支持用户指定平台和架构构建；现有 Release Action 的目标平台/架构增加 FreeBSD。
用户要求先完成代码/文档分析并提交可行性、范围、开发计划、测试方案和验收方法，确认后再编码和测试。

## 研究发现
- 当前检出分支为 `master`，与 `origin/master` 一致，最近提交为 v0.6.0 发布更新。
- 本地 origin 指向用户 Fork：`git@github.com:zls3201/OxMgr.git`；上游名称需以后续远程或仓库信息进一步核对。
- 当前仓库包含 `src/commands/deploy.rs`、`src/daemon/http.rs`、`src/process_manager/restart.rs` 等候选实现文件。
- 现有文档包含 `docs/DEPLOY.md`、`docs/PULL_WEBHOOK.md`、`docs/UI.md`、`docs/RELEASE.md`、`docs/OXFILE.md` 等候选受影响文档。
- 现有 GitHub Actions 包含 `ci.yml`、`release.yml`、`benchmark.yml`、`download-metrics.yml`；需要对比 Release 的构建矩阵和制品流程后再设计 Build Action。
- 当前阶段禁止修改实现代码和创建目标分支；规划文件是本阶段的唯一新增文件。

## 技术决策
| 决策 | 理由 |
|------|------|
| 先只读分析，不修改代码或创建分支 | 用户明确要求确认后再编码、测试 |
| 以现有实现和工作流为准设计最小差异 | 避免重复抽象和破坏既有发布流程 |

## 遇到的问题
| 问题 | 解决方案 |
|------|---------|
| “hook 相关”“Web API 相关”边界尚未明确 | 先枚举所有入口、依赖、配置和文档，再在方案中列出默认解释与需确认项 |
| `crash_restart_limit = 0` 的语义可能与“不限制”混淆 | 先追踪现有默认值、比较逻辑和文档语义，不凭名称猜测 |

## 资源
- 上游仓库：`github.com/Vladimir-Urik/OxMgr`
- 当前 Fork 远程：`git@github.com:zls3201/OxMgr.git`

## 视觉/浏览器发现
-

## 用户确认的日志路径规则
- 当 oxfile 中配置的日志路径为相对路径时，以该 oxfile 解析出的服务 `cwd` 作为基准目录。
- 当 oxfile 未配置 `cwd` 时，保留旧有逻辑，以 oxfile 所在目录作为基准。
- 绝对日志路径保持不变。
- 用户消息中的“xwd”按上下文解释为 `cwd`。

## 最近实现发现
- `.github/workflows/build.yml` 使用手动触发，支持 Linux/macOS/Windows 和 FreeBSD 的 x86_64/aarch64 目标，上传压缩包和 SHA256 文件，不创建 Release。
- `.github/workflows/release.yml` 新增独立 FreeBSD VM 构建任务，目标为 `x86_64-unknown-freebsd`，Release job 等待该任务完成。
- 原 `docs/PULL_WEBHOOK.md` 已改为 `docs/GIT_PULL.md`，仅说明本地 Git pull，避免保留过时 HTTP API/Webhook 文档。
- oxfile 已补充只配置 `combined` 日志且配置服务 `cwd` 时的相对路径测试。
- YAML 结构化解析通过；本地未发现 `cargo`、`rustc`、`rustfmt` 或 `actionlint` 可执行文件。
- FreeBSD workflow 使用 `vmactions/freebsd-vm@v1` 的 `prepare`、`run`、`envs` 和 `copyback` 参数；参考：[FreeBSD VM Action](https://github.com/marketplace/actions/freebsd-vm)。

## 静态审计补充
- 删除 `docs/DEPLOY.md` 后，已移除 `packaging/npm/README.md` 和 `CONTRIBUTING.md` 中的死链接；npm 文档路径同时修正为从 `packaging/npm/` 返回仓库根目录。
- benchmark 脚本已移除不再生效的 `TrialWorkspace.api_addr`、API 端口分配和 `OXMGR_API_ADDR` 环境变量。
- `src/js_config.rs` 注释已移除 deploy 术语。
- runtime 测试对 `i64` 重启预算到 `u32` 的转换改为饱和处理，避免未来大值窄化溢出。

## 本轮移除本地 Git 更新流程
- `oxmgr pull` 的完整链路已删除：CLI、IPC、daemon、ProcessManager、Git helper、Git 测试 fixture 和专用文档。
- `git_repo`/`git_ref` 已从运行时模型、配置解析、bundle、fingerprint、apply、doctor、status、UI、schema、文档和示例中删除；普通 GitHub、git clone、pull request 文案保留。
- 活动文件扫描不再发现本地 Git 更新入口或配置字段残留。
- 删除字段时批量属性清理曾留下重复 serde 属性；编译检查定位后已删除重复属性，并补回 spawn 测试的 `std::path::Path` 导入。
- 完整 Rust 验证通过：fmt、`cargo check --all-targets`、254 个测试、启用版 32 个 E2E 测试和严格 Clippy。

## 错误与处理
| 问题 | 处理 |
|------|------|
| `git diff --check` 报 `src/process_manager/git.rs` 文件末尾多余空行 | 删除多余空行后重新检查 |
| 删除 Git 字段后出现重复 serde 属性和无效 `Option::is_none` 序列化谓词 | 根据编译错误定位并删除重复/错误属性；重新格式化和编译通过 |

---
*每执行2次查看/浏览器/搜索操作后更新此文件*
