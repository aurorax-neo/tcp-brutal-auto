# tcp-brutal-auto

在 TCP **握手阶段**（SYN_SENT / SYN_RECV）自动给对端 IP 加上 [TCP Brutal](https://github.com/HyNetworks/tcp-brutal) 目标规则。

TCP Brutal v2 的规则 **只在连接建立时匹配**。等 `/proc/net/tcp` 出现 ESTABLISHED 再加，第一条连接已经选好拥塞算法了，加了也套不上。本程序赶在握手完成前写入规则，并调用 `brutalctl` 装上 `congctl lock brutal` 路由。

需要 Linux **5.10+**，root，以及已加载的 `brutal` 内核模块。

---

## 1. 安装 TCP Brutal 内核模块（v2）

在 **发送数据的那一台机器** 上安装（下载场景 = 服务器）。接收端不用装。

```bash
# 内核 >= 5.10
uname -r

# 官方一键安装：DKMS 模块 + /usr/local/bin/brutalctl
bash <(curl -fsSL https://tcp.hy2.sh/)
```

脚本会安装 `dkms`、对应 `linux-headers-$(uname -r)`，编译并加载模块 `brutal`。

```bash
# 确认模块
lsmod | grep brutal
cat /proc/net/tcp_brutal/rules
brutalctl list
sysctl net.ipv4.tcp_available_congestion_control   # 应含 brutal

# 开机自动加载
echo brutal | sudo tee /etc/modules-load.d/brutal.conf
```

其他命令：

```bash
bash <(curl -fsSL https://tcp.hy2.sh/) check       # 状态
bash <(curl -fsSL https://tcp.hy2.sh/)            # 升级（再跑一遍）
bash <(curl -fsSL https://tcp.hy2.sh/) uninstall  # 卸载
```

内核 < 5.10 时，安装脚本会拒绝 v2。不要把 `brutal` 设成系统默认拥塞控制：没有规则的连接会按约 **1 Mbps** 发。

手动加一条规则（本程序会自动做这件事）：

```bash
# 发往 203.0.113.5 的所有连接合计 100 Mbps
brutalctl add 203.0.113.5/32 100
brutalctl list
```

规则 **重启后丢失**。本程序的作用就是按实际对端动态加，不必手写一堆 IP。

---

## 2. 安装 tcp-brutal-auto

从 [GitHub Releases](https://github.com/aurorax-neo/tcp-brutal-auto/releases) 下载与你的系统架构对应的压缩包。支持 `x86_64` 和 `aarch64` Linux：

```bash
uname -m
```

下载并安装示例（以 `x86_64` 为例）：

```bash
VERSION=v0.1.2
TARGET=x86_64-unknown-linux-musl
curl -fLO "https://github.com/aurorax-neo/tcp-brutal-auto/releases/download/${VERSION}/tcp-brutal-auto-${VERSION}-${TARGET}.tar.gz"
curl -fLO "https://github.com/aurorax-neo/tcp-brutal-auto/releases/download/${VERSION}/tcp-brutal-auto-${VERSION}-${TARGET}.tar.gz.sha256"
sha256sum -c "tcp-brutal-auto-${VERSION}-${TARGET}.tar.gz.sha256"
tar -xzf "tcp-brutal-auto-${VERSION}-${TARGET}.tar.gz"
cd "tcp-brutal-auto-${VERSION}-${TARGET}"
sudo install -Dm755 tcp-brutal-auto /usr/local/bin/tcp-brutal-auto
sudo install -Dm644 tcp-brutal-auto.service /etc/systemd/system/tcp-brutal-auto.service
sudo install -Dm644 whitelist.example /etc/tcp-brutal-auto/whitelist.example
sudo install -Dm644 china-mainland-ipv4.txt /etc/tcp-brutal-auto/china-mainland-ipv4.txt
sudo systemctl daemon-reload
sudo systemctl enable --now tcp-brutal-auto
```

`aarch64` 用户将 `TARGET` 改为 `aarch64-unknown-linux-musl`。发布包内同时包含示例白名单和中国大陆 IPv4 白名单。

---

## 3. 运行

先空跑，确认能看到对端、且 **不会** 写规则：

```bash
sudo DRY_RUN=1 RATE=100 /usr/local/bin/tcp-brutal-auto
```

日志示例：

```
[1725600000.123] start rate=100Mbps ... dry_run=true ...
[1725600000.140] ftrace inet_sock_set_state 已启用（SYN_SENT/SYN_RECV）
[1725600001.002] dry-run add 203.0.113.5/32 100 (trace)
```

括号里是来源：`trace` / `conntrack` / `proc-syn-sent` / `proc-syn-recv` / `proc-est`。出现 `trace` 或 `proc-syn-*` 说明赶在 ESTABLISHED 之前。

确认无误后去掉 `DRY_RUN`：

```bash
sudo RATE=100 /usr/local/bin/tcp-brutal-auto
```

`RATE` 填 **接收方实际能吃下的带宽（Mbps）**。同一目标的多条连接共享这个总量。

### 环境变量

| 变量 | 默认 | 含义 |
|---|---|---|
| `RATE` | `100` | 每个对端的合计速率，Mbps |
| `INTERVAL_MS` | `0`（自动） | `/proc` 轮询间隔。自动：有事件监听时 500ms，否则 20ms |
| `INCLUDE_PRIVATE` | `0` | `1` = 也给局域网/私网加规则 |
| `WHITELIST` | 空 | 逗号分隔的 IP/CIDR；也可以是白名单文件路径 |
| `WHITELIST_FILE` | 空 | 白名单文件（每行一个 IP/CIDR，`#` 注释）。修改后最多 30 秒生效 |
| `NOROUTE` | `0` | `1` = 只写规则，不装 congctl 路由 |
| `DRY_RUN` | `0` | `1` = 只打印，不写规则、不调 brutalctl |
| `TRACE` | `1` | 内核 `inet_sock_set_state` 事件（最早） |
| `CONNTRACK` | `1` | `conntrack -E NEW`（需 conntrack-tools） |

默认 **排除** 局域网：RFC1918、CGNAT `100.64/10`、本机网卡直连网段、回环、链路本地。真要给内网加：`INCLUDE_PRIVATE=1`。

### 白名单

不设白名单时，所有公网对端都会加规则。设了之后 **只给名单里的 IP/网段加**。

```bash
# 命令行
sudo WHITELIST=203.0.113.0/24,198.51.100.8 RATE=100 tcp-brutal-auto

# 文件（推荐）
sudo cp /etc/tcp-brutal-auto/whitelist.example /etc/tcp-brutal-auto/whitelist
sudo $EDITOR /etc/tcp-brutal-auto/whitelist
sudo WHITELIST_FILE=/etc/tcp-brutal-auto/whitelist RATE=100 tcp-brutal-auto
```

systemd：

```bash
sudo systemctl edit tcp-brutal-auto
```

```
[Service]
Environment=RATE=100
Environment=WHITELIST_FILE=/etc/tcp-brutal-auto/whitelist
```

白名单可以写单个 IP（当作 /32 或 /128）或 CIDR。改文件不用重启，最多 30 秒后生效。名单为空时不加任何规则。回环和本机地址永远不加。

#### 中国大陆 IPv4 白名单

仓库中的 `data/china-mainland-ipv4.txt` 合并以下两套数据，并对结果去重、合并相邻 CIDR：

- APNIC 国家代码 `CN` 的 IPv4 分配记录
- [`appshubcc/bett-rules`](https://github.com/appshubcc/bett-rules) 发布的 CN GeoIP IPv4 规则（来源为 IPinfo Lite）

列表取两套数据的并集，用于尽量完整地覆盖中国大陆 IPv4；不主动包含香港、澳门和台湾地区。启用方法（文件在第 2 步安装时已复制到 /etc）：

```bash
sudo systemctl edit tcp-brutal-auto
```

```ini
[Service]
Environment=WHITELIST_FILE=/etc/tcp-brutal-auto/china-mainland-ipv4.txt
```

```bash
sudo systemctl restart tcp-brutal-auto
```

更新两套来源并重新生成：

```bash
./scripts/update-cn-ipv4.sh
```

APNIC 表示地址的注册分配归属，GeoIP 表示推测的实际地理位置，两者都可能存在滞后或误判。并集策略优先保证覆盖范围，可能纳入少量实际位于中国大陆以外的地址。更新列表后，需要再次安装到 `/etc/tcp-brutal-auto/`；程序会在最多 30 秒内重新加载。读取或解析新文件失败时，会继续使用上一份有效列表，不会因为临时下载失败而清空白名单。删除白名单中的网段后，由本程序创建的对应规则和路由也会自动撤销；外部创建的规则不会被修改。

可选：

```bash
sudo apt install conntrack   # Debian/Ubuntu，启用 conntrack 事件
```

---

## 4. systemd 开机启动

Release 安装命令会安装并启动 systemd 服务。手动安装或修改服务时：

```bash
sudo tee /etc/systemd/system/tcp-brutal-auto.service >/dev/null <<'EOF'
[Unit]
Description=tcp-brutal-auto — add Brutal destination rules at TCP handshake
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=RATE=100
ExecStartPre=-/sbin/modprobe brutal
ExecStart=/usr/local/bin/tcp-brutal-auto
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now tcp-brutal-auto
sudo journalctl -u tcp-brutal-auto -f
```

改速率：

```bash
sudo systemctl edit tcp-brutal-auto
# 写入：
# [Service]
# Environment=RATE=500
sudo systemctl restart tcp-brutal-auto
```

---

## 5. 验证

另开一个终端，对公网地址建连接（不要用内网 IP）：

```bash
# 本机
brutalctl list
ip route show proto 233
ss -tn state syn-recv
ss -tn state established

# 日志应出现：add 1.2.3.4/32 100 (trace)
# 新连接的拥塞算法：
ss -ti | grep -A1 1.2.3.4
# 应看到 cubic/bbr 变成 brutal（该连接若在规则之后建立）
```

---

## 6. 常见问题

**启动即退出：未找到 `/proc/net/tcp_brutal/rules`**  
模块没加载。重新跑 `bash <(curl -fsSL https://tcp.hy2.sh/)`，或 `modprobe brutal`。若刚升级过内核，先重启再装 headers。

**日志只有 `proc-est`，没有 `trace` / `syn`**  
ftrace 不可用（无 tracefs / 权限）。程序仍会加规则，但可能赶不上第一条连接。确认 `/sys/kernel/tracing/instances` 存在，并以 root 运行。

**第一条连接没吃到 Brutal**  
符合作者语义：规则必须在建立前就在。看日志时间是否早于 ESTABLISHED。公网 RTT 下 `trace` 一般够用。

**给网关/Docker 网段加了规则**  
默认会跳过私网和本机网段。若仍误加，把该网段从网卡前缀里核对一下，或保持 `INCLUDE_PRIVATE=0`。

**不要** `sysctl net.ipv4.tcp_congestion_control=brutal`。

---

## 7. 卸载

```bash
sudo systemctl disable --now tcp-brutal-auto
sudo rm -f /usr/local/bin/tcp-brutal-auto /etc/systemd/system/tcp-brutal-auto.service
sudo systemctl daemon-reload
sudo brutalctl flush
bash <(curl -fsSL https://tcp.hy2.sh/) uninstall
```

---

## 8. 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。
