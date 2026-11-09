# ⚡ Domain Scanner (分布式极速域名扫描工具)

轻量、极速、高并发的 `.com` / 通用顶级域名批量扫描与抢注检测工具。  
**纯 Python 3 标准库打造，零外部依赖**，支持多机分布式分片扫描、断点续扫、DNS 毫秒级预检与 Verisign 官方权威 RDAP 协议终验。

---

## ✨ 核心特性

- **权威精准**：直接对接 `.com` 官方管理机构 **Verisign 权威 RDAP 协议**。返回 `404 Not Found` 即代表全网绝对未注册。
- **DNS 先行初筛**：采用系统底层 DNS 解析作为一级过滤器，毫秒级剔除 85%~90% 已建站/已占用域名，大幅减少网络请求，**完全不用担心被注册局限流或封禁 IP**。
- **多机分布式分片**：原生支持 `--shard [编号]/[总数]` 参数，利用模运算实现任务全局均匀分摊，支持多台 VPS（如 US / JP / KR 节点）并行加速。
- **零配置零依赖**：不需要注册任何第三方 API Key（如 GoDaddy / Namecheap），直接开箱即用。
- **流式按需生成**：内置动态组合生成器，不依赖巨大磁盘字典文件，内存占用极低（< 20MB）。
- **断点记忆**：自动按分片与模式记录进度存盘（`checkpoint_*.json`），随时 `Ctrl+C` 暂停，下次启动无缝续扫。

---

## 🚀 快速上手

### 环境要求
- Python 3.8+（自带标准库即可，无需安装 `pip` 或任何第三方库）
- Linux / macOS / Windows

### 1. 克隆仓库
```bash
git clone https://github.com/<your-username>/domain_scanner.git
cd domain_scanner
```

### 2. 单机扫描命令

#### 🅰️ 常规无符号组合
```bash
# 扫描 3 位字母与数字严格混合 (必须包含字母与数字，共 28,080 个)
python3 domain_scanner.py 3mix

# 扫描 3 位所有组合 (字母+数字全量，共 46,656 个)
python3 domain_scanner.py 3all

# 扫描 3 位纯字母 (17,576 个) / 3 位纯数字 (1,000 个)
python3 domain_scanner.py 3letter
python3 domain_scanner.py 3num

# 扫描 4 位纯数字 (10,000 个)
python3 domain_scanner.py 4num

# 扫描 4 位纯字母 (456,976 个)
python3 domain_scanner.py 4letter

# 扫描 4 位字母数字混合 (1,212,640 个)
python3 domain_scanner.py 4mix

# 扫描 5 位纯数字 (100,000 个)
python3 domain_scanner.py 5num
```

#### 🅱️ 连字符 `-` 捡漏淘金模式（带杠米）
严格遵循 ICANN 规范：**首尾严禁为 `-`，严禁连续 `--`**。
```bash
# 4 位带杠纯字母 (仅 35,152 个，如 a-bc.com, ab-c.com，约 15 分钟即可全量扫完！)
python3 domain_scanner.py 4letter-

# 4 位带杠字母数字混合 (56,160 个，如 a-1b.com, 2z-1.com)
python3 domain_scanner.py 4mix-

# 4 位带杠纯数字 (仅 2,000 个，如 8-88.com, 12-3.com)
python3 domain_scanner.py 4num-

# 3 位带杠纯字母 (仅 676 个，如 a-b.com) / 3位带杠纯数字 (100 个)
python3 domain_scanner.py 3letter-
python3 domain_scanner.py 3num-

# 5 位带杠纯字母 (1,388,504 个，包含热门对称型如 my-app.com, go-fun.com 以及 a-b-c.com)
python3 domain_scanner.py 5letter-
```

---

## 🌐 多节点分布式并行扫描

如果你有多台服务器（如 3 台节点），**无需加 `--shard`，直接在模式后写分片 `1/3`、`2/3`、`3/3`**（分子从 1 开始，直观易懂），速度直接翻倍：

| 节点 | 运行命令 | 负责范围 |
| :--- | :--- | :--- |
| **节点 1 (如 US 节点)** | `python3 domain_scanner.py 3mix 1/3` | 负责总量的 1/3 (约 9,360 个) |
| **节点 2 (如 JP 节点)** | `python3 domain_scanner.py 3mix 2/3` | 负责总量的 1/3 (约 9,360 个) |
| **节点 3 (如 KR 节点)** | `python3 domain_scanner.py 3mix 3/3` | 负责总量的 1/3 (约 9,360 个) |

> **提示**：每个节点会独立生成自己的断点文件（如 `checkpoint_3mix_1_3.json`），互不干扰。同时依然向下兼容 `--shard 1/3` 写法。

---

## 🖥️ 后台挂机运行（防掉线）

如果你在云服务器（VPS）上扫描大字典，建议使用 `nohup` 在后台运行：

```bash
# 后台启动 (例如 3 台服务器之一)
nohup python3 domain_scanner.py 3mix 1/3 --threads 30 > scan.log 2>&1 &

# 实时查看扫描日志与进度
tail -f scan.log

# 实时查看已发现的未注册域名
cat available_domains.txt
```

---

## ⚙️ 进阶参数说明

```bash
python3 domain_scanner.py [mode] [shard] [options]
```

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `mode` | `3all` | 扫描模式：常规（`3mix`、`3all`、`3letter`、`3num`、`4mix`、`4letter`、`4num`、`4all`、`5num`、`5letter`、`5mix`、`5all`）及带杠（`3letter-`、`3num-`、`3mix-`、`3all-`、`4letter-`、`4num-`、`4mix-`、`4all-`、`5num-`、`5letter-`、`5mix-`、`5all-`） |
| `shard` / `--shard` | `1/1` | 分布式分片参数，格式为 `[当前节点编号]/[总节点数]`（**分子从 1 开始**，如 `1/3`、`2/3`、`3/3`，单机省略） |
| `--suffix` | `com` | 域名顶级后缀（如 `com`、`net` 等） |
| `--threads` | `20` | 并发线程数（单机推荐 25~40 线程） |
| `--verbose` | `False` | 是否打印每个被占用域名的详细状态（适合调试） |

---

## 📁 输出报告与文件

- **`available_<mode>.txt`**：**模式专属纯域名清单**（如 `available_3mix.txt`、`available_4all.txt`）。只存放该模式下扫出的可用域名，**不同模式彻底隔离不混杂**，纯文本一行一个，可直接 `Ctrl+A` 复制到各大注册商批量下单。
- **`available_domains.txt`**：**全局历史汇总清单**。包含历史所有模式扫出的所有可用域名，内置 **Set 自动去重机制**，重复运行绝不会产生重复行。
- **`scan_report_<mode>_<shard>.txt`**：**任务诊断总结报告**（扫描完成或按 `Ctrl+C` 暂停时自动生成）。包含扫描耗时、平均速度（QPS）、进度百分比、可用域名详细来源验证列表及平价注册商入口建议。
- **`checkpoint_<mode>_<shard>.json`**：**断点记忆文件**。自动存盘当前进度与已查数据，如果需要重新从头开始扫，直接删除该文件即可。

---

## 📄 开源许可

本项目遵循 [MIT License](LICENSE)。
