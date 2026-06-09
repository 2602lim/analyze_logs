# Windows 事件日志安全分析工具

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

读取 Windows `.evtx` 事件日志，自动识别可疑行为，输出带颜色标注的 Excel 分析报告。适用于安全应急响应、入侵排查、日志审计等场景。

---

## 功能特性

- **三类日志全覆盖**：安全日志（Security）、系统日志（System）、应用程序日志（Application）
- **自动威胁识别**：内置 30+ 条可疑事件规则，涵盖暴力破解、权限提升、持久化、横向移动等攻击技术
- **进程行为检测**：对 EventID 4688（进程创建）额外检测可疑进程名和恶意命令行关键词
- **颜色分级标注**：CRITICAL / HIGH / MEDIUM / LOW / INFO 五级告警，Excel 中直观呈现
- **结构化 Excel 报告**：包含汇总统计、可疑事件专页、各类型日志原始页、说明页
- **时区自动转换**：UTC 时间统一转换为 UTC+8 显示
- **支持批量解析**：可同时传入多个 `.evtx` 文件或使用通配符

---

## 快速开始

### 安装依赖

```bash
pip install python-evtx openpyxl
```

### 导出日志文件（在目标 Windows 机器上）

打开**事件查看器** → 左侧选择对应日志 → 右键「将所有事件另存为」→ 格式选 `.evtx`

| 日志名称 | 建议保存为 |
|---|---|
| Windows 日志 > 安全 | `Security.evtx` |
| Windows 日志 > 系统 | `System.evtx` |
| Windows 日志 > 应用程序 | `Application.evtx` |

或用 PowerShell 导出：

```powershell
wevtutil epl Security   Security.evtx
wevtutil epl System     System.evtx
wevtutil epl Application Application.evtx
```

### 运行分析

```bash
# 基本用法（分析三个日志）
python analyze_logs.py Security.evtx System.evtx Application.evtx

# 自定义输出文件名
python analyze_logs.py *.evtx -o 安全分析报告.xlsx

# 限制每个日志最大解析条数（大文件推荐）
python analyze_logs.py *.evtx --max 100000

# 自动扫描当前目录下所有 .evtx 文件
python analyze_logs.py
```

---

## 命令行参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `logs` | 一个或多个 `.evtx` 文件路径，支持通配符 | 自动扫描当前目录 |
| `-o, --output` | 输出 Excel 文件名 | `Windows日志安全分析报告.xlsx` |
| `--max` | 每个日志文件最大解析条数 | `50000` |

---

## 报告结构

生成的 Excel 文件包含以下 Sheet：

| Sheet | 内容 |
|---|---|
| 📊 汇总 | 总体统计、各日志类型数量、Top 可疑事件类型 |
| 🚨 可疑事件 | 所有非 NORMAL 事件，按威胁等级从高到低排序 |
| 🔐 Security | 安全日志全量数据 |
| ⚙️ System | 系统日志全量数据 |
| 📋 Application | 应用程序日志全量数据 |
| ℹ️ 说明 | 告警等级说明及重点事件 ID 含义 |

---

## 告警等级说明

| 等级 | 颜色 | 典型场景 |
|---|---|---|
| 🔴 CRITICAL | 红色 | 日志被清除（EventID 1102/104）、Defender 检测到恶意软件 |
| 🟠 HIGH | 橙色 | 登录失败（暴力破解）、账户创建、权限提升、计划任务植入、新服务安装 |
| 🟡 MEDIUM | 黄色 | 可疑进程启动、防火墙变更、密码重置、意外关机 |
| 🟢 LOW | 绿色 | 低危告警，需结合上下文判断 |
| 🔵 INFO | 蓝色 | 信息类事件，如成功登录、服务状态变更 |

---

## 内置检测规则

### Security 日志

| EventID | 说明 | 等级 |
|---|---|---|
| 1102 | 安全日志被清除 | CRITICAL |
| 4625 | 登录失败（暴力破解/凭据喷洒） | HIGH |
| 4648 | 显式凭据网络登录（Pass-the-Hash 特征） | HIGH |
| 4720 | 创建新用户账户 | HIGH |
| 4728/4732/4756 | 用户被加入特权组 | HIGH |
| 4698 | 创建计划任务 | HIGH |
| 4719 | 审计策略被修改 | HIGH |
| 4771 | Kerberos 预认证失败 | HIGH |
| 4740 | 账户被锁定 | HIGH |
| 4624 | 登录成功（LogonType=10 RDP 升级为 HIGH） | INFO/HIGH |
| 4688 | 进程创建（含可疑进程/命令行二次检测） | MEDIUM/HIGH |
| 4672 | 特权登录 | MEDIUM |

### System 日志

| EventID | 说明 | 等级 |
|---|---|---|
| 104 | 系统日志被清除 | CRITICAL |
| 7045 | 安装新服务 | HIGH |
| 6008 | 系统意外关机 | MEDIUM |
| 7040 | 服务启动类型被更改 | MEDIUM |

### Application 日志

| EventID | 说明 | 等级 |
|---|---|---|
| 1116/1117 | Windows Defender 检测/处置恶意软件 | CRITICAL |
| 1118/1119/1120 | Defender 清除恶意软件（成功/失败） | HIGH |
| 18456 | SQL Server 登录失败 | MEDIUM |

### 进程创建（EventID 4688）额外检测

**可疑进程名**：`powershell`、`cmd.exe`、`wscript`、`cscript`、`mshta`、`regsvr32`、`rundll32`、`certutil`、`bitsadmin`、`wmic`、`psexec`、`mimikatz`、`vssadmin`、`ntdsutil` 等

**可疑命令行关键词**：`-enc`、`-encodedcommand`、`iex(`、`downloadstring`、`bypass`、`-windowstyle hidden`、`vssadmin delete shadows`、`net user /add` 等

---

## 适用场景

- **应急响应**：主机遭受入侵后快速梳理攻击时间线
- **安全审计**：定期对服务器日志进行合规性审查
- **溯源分析**：结合告警还原攻击者行为链
- **日常运维**：批量检查多台服务器的异常登录、账户变更

---

## 注意事项

- 导出 `.evtx` 需要管理员权限
- 日志文件较大时（>500MB）建议配合 `--max` 参数控制解析量
- 本工具仅做静态日志分析，不会对目标系统做任何修改
- 部分告警（如 4648、4672）在正常系统中也会产生，需结合上下文人工研判

---

## 依赖环境

| 依赖 | 版本 | 用途 |
|---|---|---|
| Python | 3.8+ | 运行环境 |
| python-evtx | 最新版 | 解析 .evtx 二进制文件 |
| openpyxl | 最新版 | 生成 Excel 报告 |

---

## License

MIT License — 可自由用于个人和商业用途，欢迎提交 Issue 和 PR。
