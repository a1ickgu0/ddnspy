# ddnspy — Cloudflare DDNS 更新器

读取 JSON 配置文件，检测本机的公网 IPv4/IPv6 地址，并自动同步到 Cloudflare DNS 记录。
专为 Debian / 树莓派 OS 等 Linux 发行版设计为 **systemd 服务**运行，也可以作为一次性命令用于测试或 cron。

- 仅依赖 Python 3 标准库（≥ 3.8），无需 pip 安装任何东西
- 支持多条 DNS 记录、并行更新、IPv4/IPv6（A / AAAA）
- IP 检测方式：外部端点（默认，强制走对应协议栈，双栈端点如 `ip.sb` 也能返回正确版本）或本地网卡读取
- 记录不存在时可自动创建（`create_if_missing`），退出时可选择删除（`delete_on_exit`）
- 只在 IP / proxied / TTL 变化时才调用更新接口，平时零 API 写请求

## 文件说明

| 文件 | 用途 |
|---|---|
| `ddnspy.py` | 主程序（标准库实现） |
| `config.json` | 真实配置（含 token，已被 `.gitignore` 排除，不要提交） |
| `config.example.json` | 配置模板（占位 token） |
| `ddnspy.service` | systemd 服务单元 |
| `install.sh` / `uninstall.sh` | 一键安装 / 卸载为 systemd 服务 |

## 快速测试（开发机 macOS / Linux 均可）

```bash
# 1. 演练：只做检测和对比，不改动 Cloudflare
python3 ddnspy.py --config config.json --dry-run --once

# 2. 真实执行一次同步
python3 ddnspy.py --config config.json --once

# 3. 验证解析结果
dig @1.1.1.1 ddns.alickguo.me A +short
```

其他常用参数：`--daemon` 强制常驻运行、`-v` 调试日志、`--version`。
不带 `--once/--daemon` 时，模式由配置里的 `app.once` / `app.daemon` 决定
（当前 `daemon: false` → 默认单次执行后退出）。

## 部署为 systemd 服务（Debian / 树莓派 / Ubuntu）

```bash
sudo ./install.sh
```

安装脚本会：

1. 创建无登录的系统用户 `ddnspy`
2. 安装主程序到 `/usr/local/bin/ddnspy`
3. 安装配置到 `/etc/ddnspy/config.json`（权限 `0640 root:ddnspy`；已存在则不覆盖，另存为 `config.json.new`）
4. 创建日志目录 `/var/log/ddnspy`
5. 安装并启用 `ddnspy.service`（开机自启、失败自动重启、最小权限加固）

日常操作：

```bash
systemctl status ddnspy          # 运行状态
journalctl -u ddnspy -f          # 跟踪日志（默认日志走 stdout → journald）
sudoedit /etc/ddnspy/config.json # 改配置后：sudo systemctl restart ddnspy
sudo ./uninstall.sh              # 卸载（/etc/ddnspy 下的配置会保留）
```

> 树莓派 / Debian 上请把 `wan.interfaces[].name` 与 `wan.default_interface`
> 从 macOS 的 `en0` 改成实际网卡名（`eth0` / `wlan0` 等，`ip addr` 查看）。
> 不过默认 `use_external_detect: true` 时公网 IP 来自外部端点，不依赖网卡名也能工作。

## 配置说明（主要字段）

### `cloudflare`
| 字段 | 说明 |
|---|---|
| `api_token` | Cloudflare API Token（Bearer 方式认证），对所有 zone 生效（`use_shared_token`） |

### `records[]`（每个元素一条 DNS 记录）
| 字段 | 说明 |
|---|---|
| `zone_name` / `record_name` / `record_type` | 域名（如 `alickguo.me`）/ 完整记录名（如 `ddns.alickguo.me`）/ `A` 或 `AAAA` |
| `ttl` / `proxied` | TTL 秒数（proxied 时由 Cloudflare 强制为 auto）；是否走 Cloudflare 代理 |
| `check_interval` | 该记录的检查周期（秒），缺省用 `global_settings.default_check_interval` |
| `update_on_change` | `true`：仅当 IP/proxied/TTL 变化时更新（推荐）；`false`：每个周期强制推送一次 |
| `create_if_missing` | 记录不存在时是否自动创建 |
| `delete_on_exit` | `true` 时守护进程退出会删除该记录（域名将无法解析，慎用） |
| `binding_mode` / `wan_interface` | `auto`：按 `priority` 自动选择可用出口；`interface`：绑定指定网卡（填 `wan_interface`） |

### `wan.interfaces[]`
按 `priority` 升序作为检测来源（也即多出口 failover 顺序）；`use_external_detect`
走外部端点测公网 IP，`use_local_read` 直接读网卡地址。`wan.check_interval`
为检测结果的缓存有效期。

### `app`
`daemon`（常驻运行）、`once`（单次执行）、`log_level` / `verbose`（日志级别）、
`log_path`（写文件，留空则只输出 stdout/journald；若填写请放在 `/var/log/ddnspy/` 下，服务单元只对该目录可写）。

## API Token 权限建议

Cloudflare 控制台 → My Profile → API Tokens → Create Token，选择
**"Edit zone DNS"** 模板并限定 Zone 为你的域名（如 `alickguo.me`）即可：
需要 `Zone → Zone → Read` 和 `Zone → DNS → Edit` 两个权限。
不要使用 Global API Key。程序启动时会调用 `/user/tokens/verify` 校验 token。

## 常见问题

- **token 校验失败 / 403**：token 无效或权限不足，按上面建议重建 token。
- **找不到 zone**：token 未授权该 zone，或 `zone_name` 拼写错误。
- **同名多条记录**：程序只管理第一条并在日志中告警，请到 Cloudflare 控制台清理重复记录。
- **IPv6（AAAA）**：把 `record_type` 设为 `AAAA`，并在接口上打开 `detect_ipv6`（外部检测会强制走 IPv6 端点）。
- **cron 方式运行**：`*/5 * * * * /usr/local/bin/ddnspy --once --config /etc/ddnspy/config.json`。
