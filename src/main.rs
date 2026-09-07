//! tcp-brutal 自动加规则：在 SYN 阶段加，而不是等 ESTABLISHED。
//!
//! 作者明确写了：连接只在建立时匹配规则，必须先加规则再完成握手。
//! brutal_init() → brutal_apply_rule() 发生在三次握手完成的那一刻。
//! 旧逻辑轮询 /proc/net/tcp 的 ESTABLISHED，等于握手完了才加，第一条连接永远吃不到。
//!
//! 本程序按优先级启用三种监听（能用的都开，互为兜底）：
//!   1. ftrace inet_sock_set_state（SYN_SENT / SYN_RECV，内核状态变化即时通知）
//!   2. conntrack -E NEW（SYN 包进 conntrack 就通知）
//!   3. 轮询 /proc/net/tcp{,6} 的 SYN_* + ESTABLISHED（兜底）
//!
//! 看到对端 IP 后立刻写入 /proc/net/tcp_brutal/rules（微秒级），
//! 再异步调用 brutalctl 补 congctl lock brutal 路由。
//! 入站连接从 SYN 到最终 ACK 有一整轮 RTT，这段窗口刚好够把规则和路由装上。
//!
//! 编译: cargo build --release
//! 运行: RATE=100 ./target/release/tcp-brutal-auto
//!
//! 环境变量:
//!   RATE              目标速率 Mbps (默认 100)
//!   INTERVAL_MS       /proc 轮询间隔，0=自动（有事件监听时 500ms，否则 20ms）
//!   INCLUDE_PRIVATE   1=也给局域网/私网加规则（默认排除 RFC1918、CGNAT 100.64/10、本机网段）
//!   WHITELIST         逗号分隔的 IP/CIDR，只给名单内对端加规则（可同时是文件路径）
//!   WHITELIST_FILE    白名单文件，每行一个 IP 或 CIDR，# 开头为注释；修改后最多 30s 生效
//!   NOROUTE           1=只写规则不加 congctl 路由
//!   DRY_RUN           1=只打印不加
//!   TRACE             1=尝试 ftrace (默认 1)
//!   CONNTRACK         1=尝试 conntrack -E (默认 1)

use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RULES_PATH: &str = "/proc/net/tcp_brutal/rules";
const TCP4: &str = "/proc/net/tcp";
const TCP6: &str = "/proc/net/tcp6";

const TCP_ESTABLISHED: u8 = 0x01;
const TCP_SYN_SENT: u8 = 0x02;
const TCP_SYN_RECV: u8 = 0x03;
const TCP_NEW_SYN_RECV: u8 = 0x0C;

#[derive(Clone)]
struct Config {
    rate_mbps: f64,
    interval_ms: u64,
    include_private: bool,
    noroute: bool,
    dry_run: bool,
    trace: bool,
    conntrack: bool,
    whitelist_on: bool,
    whitelist_file: Option<PathBuf>,
    whitelist_inline: Vec<NetPrefix>,
}

struct Shared {
    cfg: Config,
    known: Mutex<HashSet<IpAddr>>,
    local: Mutex<HashSet<IpAddr>>,
    local_nets: Mutex<Vec<NetPrefix>>,
    whitelist: Mutex<PrefixSet>,
    managed: Mutex<HashSet<IpAddr>>,
    have_events: AtomicBool,
}

#[derive(Clone, Debug, Default)]
struct PrefixSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl PrefixSet {
    fn from_prefixes(prefixes: Vec<NetPrefix>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for prefix in prefixes {
            match prefix.addr {
                IpAddr::V4(addr) => {
                    let start = u32::from(addr)
                        & if prefix.plen == 0 {
                            0
                        } else {
                            u32::MAX << (32 - prefix.plen)
                        };
                    let end = start
                        | if prefix.plen == 32 {
                            0
                        } else {
                            u32::MAX >> prefix.plen
                        };
                    v4.push((start, end));
                }
                IpAddr::V6(addr) => {
                    let start = u128::from(addr)
                        & if prefix.plen == 0 {
                            0
                        } else {
                            u128::MAX << (128 - prefix.plen)
                        };
                    let end = start
                        | if prefix.plen == 128 {
                            0
                        } else {
                            u128::MAX >> prefix.plen
                        };
                    v6.push((start, end));
                }
            }
        }
        v4.sort_unstable_by_key(|(start, _)| *start);
        v6.sort_unstable_by_key(|(start, _)| *start);
        Self {
            v4: merge_v4_ranges(v4),
            v6: merge_v6_ranges(v6),
        }
    }

    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(addr) => range_contains_v4(&self.v4, u32::from(addr)),
            IpAddr::V6(addr) => range_contains_v6(&self.v6, u128::from(addr)),
        }
    }
}

fn merge_v4_ranges(ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    let mut merged = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, current_end)) = merged.last_mut() {
            if start <= *current_end || (*current_end < u32::MAX && start == *current_end + 1) {
                *current_end = (*current_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn merge_v6_ranges(ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    let mut merged = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, current_end)) = merged.last_mut() {
            if start <= *current_end || (*current_end < u128::MAX && start == *current_end + 1) {
                *current_end = (*current_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn range_contains_v4(ranges: &[(u32, u32)], value: u32) -> bool {
    let mut low = 0;
    let mut high = ranges.len();
    while low < high {
        let mid = (low + high) / 2;
        if ranges[mid].0 <= value {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low > 0 && value <= ranges[low - 1].1
}

fn range_contains_v6(ranges: &[(u128, u128)], value: u128) -> bool {
    let mut low = 0;
    let mut high = ranges.len();
    while low < high {
        let mid = (low + high) / 2;
        if ranges[mid].0 <= value {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low > 0 && value <= ranges[low - 1].1
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NetPrefix {
    addr: IpAddr,
    plen: u8,
}

impl NetPrefix {
    fn parse(s: &str) -> Option<Self> {
        let (host, plen) = match s.split_once('/') {
            Some((h, p)) => (h, p.parse().ok()?),
            None => {
                let ip: IpAddr = s.parse().ok()?;
                let plen = if ip.is_ipv4() { 32 } else { 128 };
                return Some(Self {
                    addr: canonicalize(ip),
                    plen,
                });
            }
        };
        let addr: IpAddr = host.parse().ok()?;
        let addr = canonicalize(addr);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if plen > max {
            return None;
        }
        Some(Self { addr, plen })
    }

    fn is_subnet(&self) -> bool {
        match self.addr {
            IpAddr::V4(_) => self.plen > 0 && self.plen < 32,
            IpAddr::V6(_) => self.plen > 0 && self.plen < 128,
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(host)) => {
                let shift = 32u32.saturating_sub(self.plen as u32);
                let mask = if self.plen == 0 { 0 } else { u32::MAX << shift };
                (u32::from(net) & mask) == (u32::from(host) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(host)) => {
                let shift = 128u32.saturating_sub(self.plen as u32);
                let mask = if self.plen == 0 {
                    0
                } else {
                    u128::MAX << shift
                };
                (u128::from(net) & mask) == (u128::from(host) & mask)
            }
            _ => false,
        }
    }
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(s) => matches!(s.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"),
        Err(_) => default,
    }
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn load_config() -> Result<Config, String> {
    let wl_env = env_opt("WHITELIST");
    let wl_file_env = env_opt("WHITELIST_FILE");
    let mut whitelist_file = wl_file_env.map(PathBuf::from);
    let mut whitelist_inline = Vec::new();
    if let Some(raw) = wl_env {
        let p = PathBuf::from(&raw);
        if p.is_file() || raw.contains('/') {
            whitelist_file = Some(p);
        } else {
            whitelist_inline = parse_whitelist_text(&raw)?;
        }
    }
    let whitelist_on = whitelist_file.is_some() || !whitelist_inline.is_empty();
    Ok(Config {
        rate_mbps: env_f64("RATE", 100.0),
        interval_ms: env_u64("INTERVAL_MS", 0),
        include_private: env_bool("INCLUDE_PRIVATE", false),
        noroute: env_bool("NOROUTE", false),
        dry_run: env_bool("DRY_RUN", false),
        trace: env_bool("TRACE", true),
        conntrack: env_bool("CONNTRACK", true),
        whitelist_on,
        whitelist_file,
        whitelist_inline,
    })
}

fn parse_whitelist_text(text: &str) -> Result<Vec<NetPrefix>, String> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("");
        for tok in line.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            if tok.is_empty() {
                continue;
            }
            let prefix = NetPrefix::parse(tok).ok_or_else(|| format!("whitelist 无效项: {tok}"))?;
            if !out.iter().any(|entry: &NetPrefix| entry == &prefix) {
                out.push(prefix);
            }
        }
    }
    Ok(out)
}

fn load_whitelist(cfg: &Config) -> Result<PrefixSet, String> {
    let mut nets = cfg.whitelist_inline.clone();
    if let Some(path) = &cfg.whitelist_file {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("读白名单 {} 失败: {e}", path.display()))?;
        nets.extend(parse_whitelist_text(&text)?);
    }
    Ok(PrefixSet::from_prefixes(nets))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn is_always_skip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_unspecified()
                || v.is_loopback()
                || v.is_broadcast()
                || v.is_link_local()
                || v.is_multicast()
        }
        IpAddr::V6(v) => {
            v.is_unspecified() || v.is_loopback() || v.is_multicast() || v.is_unicast_link_local()
        }
    }
}

fn is_lan_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let n = u32::from(v);
            v.is_private()
                || v.is_documentation()
                || (n & 0xffc0_0000) == 0x6440_0000 // 100.64.0.0/10 CGNAT
                || (n & 0xfffe_0000) == 0xc612_0000 // 198.18.0.0/15 benchmarking
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_unique_local() || is_v6_site_local(v) || (s[0] == 0x2001 && s[1] == 0x0db8)
            // 2001:db8::/32
        }
    }
}

fn is_v6_site_local(v: Ipv6Addr) -> bool {
    (v.segments()[0] & 0xffc0) == 0xfec0
}

fn in_nets(ip: IpAddr, nets: &PrefixSet) -> bool {
    nets.contains(ip)
}

fn should_skip(ip: IpAddr, shared: &Shared) -> bool {
    if is_always_skip(ip) {
        return true;
    }
    if lock(&shared.local).contains(&ip) {
        return true;
    }
    if shared.cfg.whitelist_on {
        return !in_nets(ip, &lock(&shared.whitelist));
    }
    if shared.cfg.include_private {
        return false;
    }
    if is_lan_addr(ip) {
        return true;
    }
    lock(&shared.local_nets)
        .iter()
        .any(|n| n.is_subnet() && n.contains(ip))
}

fn prefix_of(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    }
}

fn canonicalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        other => other,
    }
}

fn parse_hex_u32_le(s: &str) -> Option<u32> {
    u32::from_str_radix(s, 16).ok()
}

fn parse_ipv4_hex(s: &str) -> Option<IpAddr> {
    let n = parse_hex_u32_le(s)?;
    Some(IpAddr::V4(std::net::Ipv4Addr::from(n.to_le_bytes())))
}

fn parse_ipv6_hex(s: &str) -> Option<IpAddr> {
    if s.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let chunk = &s[i * 8..i * 8 + 8];
        let n = parse_hex_u32_le(chunk)?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&n.to_le_bytes());
    }
    Some(canonicalize(IpAddr::V6(std::net::Ipv6Addr::from(bytes))))
}

fn want_state(st: u8) -> bool {
    matches!(
        st,
        TCP_ESTABLISHED | TCP_SYN_SENT | TCP_SYN_RECV | TCP_NEW_SYN_RECV
    )
}

fn for_each_proc_tcp(path: &str, v6: bool, mut f: impl FnMut(IpAddr, u8)) {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return,
        Err(e) => {
            log_line(&format!("read {path}: {e}"));
            return;
        }
    };
    for (i, line) in io::BufReader::new(file).lines().enumerate() {
        let Ok(line) = line else { continue };
        if i == 0 {
            continue;
        }
        let mut it = line.split_whitespace();
        let _sl = it.next();
        let _local = it.next();
        let Some(rem) = it.next() else { continue };
        let Some(st_s) = it.next() else { continue };
        let st = u8::from_str_radix(st_s, 16).unwrap_or(0);
        if !want_state(st) {
            continue;
        }
        let hex = rem.split_once(':').map(|(ip, _)| ip).unwrap_or("");
        let ip = if v6 {
            parse_ipv6_hex(hex)
        } else {
            parse_ipv4_hex(hex)
        };
        if let Some(ip) = ip {
            f(ip, st);
        }
    }
}

fn load_existing_rules() -> HashSet<IpAddr> {
    let mut set = HashSet::new();
    let Ok(text) = fs::read_to_string(RULES_PATH) else {
        return set;
    };
    for line in text.lines() {
        for part in line.split_whitespace() {
            let Some(dst) = part.strip_prefix("dst=") else {
                continue;
            };
            let host = dst.split('/').next().unwrap_or(dst);
            if let Ok(ip) = host.parse::<IpAddr>() {
                set.insert(canonicalize(ip));
            }
        }
    }
    set
}

fn write_rule(prefix: &str, rate_mbps: f64) -> io::Result<()> {
    let rate_bps = (rate_mbps * 1_000_000.0 / 8.0 + 0.5) as u64;
    let command = format!("add {prefix} rate={rate_bps}\n");
    let mut f = fs::OpenOptions::new().write(true).open(RULES_PATH)?;
    let written = f.write(command.as_bytes())?;
    if written != command.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "tcp-brutal rules command was only partially written",
        ));
    }
    Ok(())
}

fn delete_rule(prefix: &str) -> io::Result<()> {
    let command = format!("del {prefix}\n");
    let mut f = fs::OpenOptions::new().write(true).open(RULES_PATH)?;
    let written = f.write(command.as_bytes())?;
    if written != command.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "tcp-brutal delete command was only partially written",
        ));
    }
    Ok(())
}

fn brutalctl_add(prefix: &str, rate: f64, noroute: bool) -> Result<(), String> {
    let mut cmd = Command::new("brutalctl");
    cmd.arg("add").arg(prefix).arg(rate.to_string());
    if noroute {
        cmd.arg("noroute");
    }
    let output = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("执行 brutalctl 失败: {e}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() || stderr.contains("rule added") {
        return Ok(());
    }
    Err(stderr.trim().to_string())
}

fn log_line(msg: &str) {
    let ts = now_stamp();
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{ts} {msg}");
    let _ = stdout.flush();
}

fn now_stamp() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("[{}.{:03}]", d.as_secs(), d.subsec_millis())
}

fn find_in_path(name: &str) -> bool {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .any(|d| Path::new(d).join(name).is_file())
}

fn kv_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let i = line.find(key)?;
    let rest = &line[i + key.len()..];
    Some(rest.split_whitespace().next()?.trim_end_matches(','))
}

fn parse_ip_token(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok().map(canonicalize)
}

enum Action {
    Add(IpAddr, &'static str),
    Delete(IpAddr),
}

fn brutalctl_del(prefix: &str) -> Result<(), String> {
    let output = Command::new("brutalctl")
        .arg("del")
        .arg(prefix)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("执行 brutalctl del 失败: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn submit(ip: IpAddr, shared: &Shared, tx: &Sender<Action>, why: &'static str) {
    let ip = canonicalize(ip);
    if should_skip(ip, shared) {
        return;
    }
    {
        let mut known = lock(&shared.known);
        if !known.insert(ip) {
            return;
        }
    }
    let prefix = prefix_of(ip);
    if shared.cfg.dry_run {
        log_line(&format!(
            "dry-run add {prefix} {} ({why})",
            shared.cfg.rate_mbps
        ));
        return;
    }
    // 规则必须在 brutal_init（握手完成）之前进内核。这里同步写入 procfs，
    // 不走 fork，通常几十微秒就能完成。
    if let Err(e) = write_rule(&prefix, shared.cfg.rate_mbps) {
        log_line(&format!("write {prefix}: {e}"));
        lock(&shared.known).remove(&ip);
        return;
    }
    lock(&shared.managed).insert(ip);
    if tx.send(Action::Add(ip, why)).is_err() {
        lock(&shared.known).remove(&ip);
        lock(&shared.managed).remove(&ip);
        let _ = delete_rule(&prefix);
        log_line(&format!(
            "add {prefix} {} ({why}, rule-only; worker dead)",
            shared.cfg.rate_mbps
        ));
    }
}

fn spawn_worker(shared: Arc<Shared>, rx: mpsc::Receiver<Action>) {
    thread::Builder::new()
        .name("brutalctl".into())
        .spawn(move || {
            for action in rx {
                let (ip, why, deleting) = match action {
                    Action::Add(ip, why) => (ip, why, false),
                    Action::Delete(ip) => (ip, "whitelist", true),
                };
                let prefix = prefix_of(ip);
                if deleting {
                    match brutalctl_del(&prefix) {
                        Ok(()) => log_line(&format!("del {prefix} ({why})")),
                        Err(e) => {
                            lock(&shared.managed).insert(ip);
                            log_line(&format!("fail del {prefix}: {e}"));
                        }
                    }
                    continue;
                }
                if shared.cfg.noroute {
                    log_line(&format!(
                        "add {prefix} {} ({why}, noroute)",
                        shared.cfg.rate_mbps
                    ));
                    continue;
                }
                match brutalctl_add(&prefix, shared.cfg.rate_mbps, false) {
                    Ok(()) => log_line(&format!("add {prefix} {} ({why})", shared.cfg.rate_mbps)),
                    Err(e) => {
                        lock(&shared.known).remove(&ip);
                        lock(&shared.managed).remove(&ip);
                        let _ = delete_rule(&prefix);
                        log_line(&format!("fail {prefix}: {e}"));
                    }
                }
            }
        })
        .expect("spawn worker");
}

fn tracing_root() -> Option<&'static str> {
    const CANDIDATES: &[&str] = &["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];
    for p in CANDIDATES {
        if Path::new(&format!("{p}/instances")).is_dir() {
            return Some(*p);
        }
    }
    None
}

struct TraceGuard {
    path: PathBuf,
}

impl Drop for TraceGuard {
    fn drop(&mut self) {
        let _ = fs::write(self.path.join("tracing_on"), b"0");
        let _ = fs::write(
            self.path.join("events/sock/inet_sock_set_state/enable"),
            b"0",
        );
        let _ = fs::write(self.path.join("set_event"), b"");
        let _ = fs::remove_dir(&self.path);
    }
}

fn setup_trace() -> io::Result<(fs::File, TraceGuard)> {
    let root = tracing_root()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "tracefs instances 不可用"))?;
    let inst = PathBuf::from(format!("{root}/instances/tcp_brutal_auto"));
    fs::create_dir_all(&inst)?;
    let ev = inst.join("events/sock/inet_sock_set_state");
    // 只订阅握手状态，避免 ESTABLISHED/FIN 把管道打满。
    let _ = fs::write(
        ev.join("filter"),
        b"newstate == 2 || newstate == 3 || newstate == 12\n",
    );
    fs::write(ev.join("enable"), b"1")?;
    fs::write(inst.join("tracing_on"), b"1")?;
    let pipe = fs::OpenOptions::new()
        .read(true)
        .open(inst.join("trace_pipe"))?;
    Ok((pipe, TraceGuard { path: inst }))
}

fn parse_trace_line(line: &str) -> Option<IpAddr> {
    let st = kv_after(line, "newstate=")?;
    let handshake = matches!(
        st,
        "TCP_SYN_SENT"
            | "TCP_SYN_RECV"
            | "TCP_NEW_SYN_RECV"
            | "SYN_SENT"
            | "SYN_RECV"
            | "NEW_SYN_RECV"
            | "2"
            | "3"
            | "12"
    );
    if !handshake {
        return None;
    }
    let family = kv_after(line, "family=").unwrap_or("");
    let is_v6 = family == "AF_INET6" || family == "10";
    if is_v6 {
        kv_after(line, "daddrv6=")
            .and_then(parse_ip_token)
            .or_else(|| kv_after(line, "daddr=").and_then(parse_ip_token))
    } else {
        kv_after(line, "daddr=").and_then(parse_ip_token)
    }
}

fn spawn_trace(shared: Arc<Shared>, tx: Sender<Action>) {
    if !shared.cfg.trace {
        return;
    }
    thread::Builder::new()
        .name("trace".into())
        .spawn(move || {
            let (pipe, _guard) = match setup_trace() {
                Ok(v) => v,
                Err(e) => {
                    log_line(&format!("ftrace 不可用 ({e})，跳过内核状态事件"));
                    return;
                }
            };
            shared.have_events.store(true, Ordering::Relaxed);
            log_line("ftrace inet_sock_set_state 已启用（SYN_SENT/SYN_RECV）");
            let reader = io::BufReader::with_capacity(64 * 1024, pipe);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if let Some(ip) = parse_trace_line(&line) {
                    submit(ip, &shared, &tx, "trace");
                }
            }
            log_line("ftrace 监听结束");
        })
        .ok();
}

fn load_local() -> (HashSet<IpAddr>, Vec<NetPrefix>) {
    let mut ips = HashSet::new();
    let mut nets = Vec::new();
    if let Ok(out) = Command::new("ip")
        .args(["-o", "addr", "show"])
        .stdin(Stdio::null())
        .output()
    {
        if out.status.success() {
            parse_ip_addr_show(&String::from_utf8_lossy(&out.stdout), &mut ips, &mut nets);
        }
    }
    if ips.is_empty() {
        if let Ok(text) = fs::read_to_string("/proc/net/fib_trie") {
            parse_fib_trie_local(&text, &mut ips);
        }
        if let Ok(text) = fs::read_to_string("/proc/net/if_inet6") {
            parse_if_inet6(&text, &mut ips);
        }
    }
    (ips, nets)
}

fn parse_ip_addr_show(text: &str, ips: &mut HashSet<IpAddr>, nets: &mut Vec<NetPrefix>) {
    for line in text.lines() {
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "inet" || tok == "inet6" {
                if let Some(addr) = it.next() {
                    if let Some(net) = NetPrefix::parse(addr) {
                        ips.insert(net.addr);
                        if net.is_subnet() && !nets.iter().any(|n| n == &net) {
                            nets.push(net);
                        }
                    }
                }
            }
        }
    }
}

fn parse_fib_trie_local(text: &str, set: &mut HashSet<IpAddr>) {
    let mut prev: Option<IpAddr> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.contains("host LOCAL") {
            if let Some(ip) = prev {
                set.insert(ip);
            }
        }
        let rest = t.strip_prefix("|-- ").or_else(|| t.strip_prefix("+-- "));
        if let Some(rest) = rest {
            let ipstr = rest.split_whitespace().next().unwrap_or("");
            prev = ipstr.parse().ok();
        }
    }
}

fn parse_if_inet6(text: &str, set: &mut HashSet<IpAddr>) {
    for line in text.lines() {
        let Some(hex) = line.split_whitespace().next() else {
            continue;
        };
        if hex.len() != 32 {
            continue;
        }
        let mut bytes = [0u8; 16];
        let mut ok = true;
        for i in 0..16 {
            match u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                Ok(b) => bytes[i] = b,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            set.insert(canonicalize(IpAddr::V6(std::net::Ipv6Addr::from(bytes))));
        }
    }
}

fn peer_from_conntrack(line: &str, local: &HashSet<IpAddr>) -> Option<IpAddr> {
    let mut src = None;
    let mut dst = None;
    for part in line.split_whitespace() {
        if src.is_none() {
            if let Some(v) = part.strip_prefix("src=") {
                src = parse_ip_token(v);
                continue;
            }
        }
        if dst.is_none() {
            if let Some(v) = part.strip_prefix("dst=") {
                dst = parse_ip_token(v);
                continue;
            }
        }
        if src.is_some() && dst.is_some() {
            break;
        }
    }
    let src = src?;
    let dst = dst?;
    let src_local = local.contains(&src)
        || match src {
            IpAddr::V4(v) => v.is_loopback(),
            IpAddr::V6(v) => v.is_loopback(),
        };
    let dst_local = local.contains(&dst)
        || match dst {
            IpAddr::V4(v) => v.is_loopback(),
            IpAddr::V6(v) => v.is_loopback(),
        };
    match (src_local, dst_local) {
        (true, false) => Some(dst),
        (false, true) => Some(src),
        _ => None,
    }
}

fn spawn_conntrack(shared: Arc<Shared>, tx: Sender<Action>) {
    if !shared.cfg.conntrack {
        return;
    }
    if !find_in_path("conntrack") {
        log_line("未找到 conntrack 命令，跳过 netfilter 事件");
        return;
    }
    thread::Builder::new()
        .name("conntrack".into())
        .spawn(move || {
            let mut child = match Command::new("conntrack")
                .args(["-E", "-p", "tcp", "-e", "NEW"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    log_line(&format!("conntrack -E 启动失败 ({e})"));
                    return;
                }
            };
            let stdout = match child.stdout.take() {
                Some(s) => s,
                None => return,
            };
            shared.have_events.store(true, Ordering::Relaxed);
            log_line("conntrack -E NEW 已启用");
            let reader = io::BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let local = lock(&shared.local);
                if let Some(ip) = peer_from_conntrack(&line, &local) {
                    drop(local);
                    submit(ip, &shared, &tx, "conntrack");
                }
            }
            let _ = child.wait();
            log_line("conntrack 事件监听结束");
        })
        .ok();
}

fn main() {
    let cfg = match load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("配置错误: {e}");
            std::process::exit(2);
        }
    };
    if fs::metadata(RULES_PATH).is_err() {
        let _ = Command::new("modprobe").arg("brutal").status();
    }
    if fs::metadata(RULES_PATH).is_err() {
        if cfg.dry_run {
            log_line(&format!(
                "未找到 {RULES_PATH}，DRY_RUN 下继续（不会真正写规则）"
            ));
        } else {
            eprintln!("未找到 {RULES_PATH}，确认 tcp-brutal 模块已加载");
            eprintln!("安装: bash <(curl -fsSL https://tcp.hy2.sh/)");
            std::process::exit(1);
        }
    }
    if !cfg.dry_run && !find_in_path("brutalctl") && !cfg.noroute {
        log_line("警告: PATH 中没有 brutalctl，只能写入规则、无法安装 congctl 路由");
    }

    let known = load_existing_rules();
    let (local, local_nets) = load_local();
    let whitelist = match load_whitelist(&cfg) {
        Ok(whitelist) => whitelist,
        Err(e) => {
            eprintln!("白名单错误: {e}");
            std::process::exit(2);
        }
    };
    if cfg.whitelist_on {
        log_line(&format!(
            "whitelist on entries={} file={}",
            whitelist.len(),
            cfg.whitelist_file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".into())
        ));
        if whitelist.is_empty() {
            log_line("白名单为空，不会给任何对端加规则");
        }
    }
    log_line(&format!(
        "start rate={}Mbps interval={}ms private={} noroute={} dry_run={} trace={} conntrack={} whitelist={} existing={} local_ips={} lan_nets={}",
        cfg.rate_mbps,
        if cfg.interval_ms == 0 { 0 } else { cfg.interval_ms },
        cfg.include_private,
        cfg.noroute,
        cfg.dry_run,
        cfg.trace,
        cfg.conntrack,
        whitelist.len(),
        known.len(),
        local.len(),
        local_nets.len()
    ));

    let shared = Arc::new(Shared {
        cfg: cfg.clone(),
        known: Mutex::new(known),
        local: Mutex::new(local),
        local_nets: Mutex::new(local_nets),
        whitelist: Mutex::new(whitelist),
        managed: Mutex::new(HashSet::new()),
        have_events: AtomicBool::new(false),
    });

    let (tx, rx) = mpsc::channel();
    spawn_worker(Arc::clone(&shared), rx);
    spawn_trace(Arc::clone(&shared), tx.clone());
    spawn_conntrack(Arc::clone(&shared), tx.clone());

    let mut last_local_refresh = Instant::now();
    let mut last_audit = Instant::now();
    loop {
        for_each_proc_tcp(TCP4, false, |ip, st| {
            let why: &'static str = match st {
                TCP_SYN_SENT => "proc-syn-sent",
                TCP_SYN_RECV | TCP_NEW_SYN_RECV => "proc-syn-recv",
                _ => "proc-est",
            };
            submit(ip, &shared, &tx, why);
        });
        for_each_proc_tcp(TCP6, true, |ip, st| {
            let why: &'static str = match st {
                TCP_SYN_SENT => "proc-syn-sent",
                TCP_SYN_RECV | TCP_NEW_SYN_RECV => "proc-syn-recv",
                _ => "proc-est",
            };
            submit(ip, &shared, &tx, why);
        });

        if last_local_refresh.elapsed() >= Duration::from_secs(30) {
            let (ips, nets) = load_local();
            *lock(&shared.local) = ips;
            *lock(&shared.local_nets) = nets;
            if shared.cfg.whitelist_on {
                match load_whitelist(&shared.cfg) {
                    Ok(new_whitelist) => {
                        let removed: Vec<IpAddr> = lock(&shared.managed)
                            .iter()
                            .copied()
                            .filter(|ip| !new_whitelist.contains(*ip))
                            .collect();
                        for ip in removed {
                            lock(&shared.managed).remove(&ip);
                            lock(&shared.known).remove(&ip);
                            if tx.send(Action::Delete(ip)).is_err() {
                                lock(&shared.managed).insert(ip);
                            }
                        }
                        *lock(&shared.whitelist) = new_whitelist;
                    }
                    Err(e) => log_line(&format!("白名单更新失败，继续使用上一版本: {e}")),
                }
            }
            last_local_refresh = Instant::now();
        }

        if last_audit.elapsed() >= Duration::from_secs(5) {
            last_audit = Instant::now();
            if !shared.cfg.dry_run {
                let actual = load_existing_rules();
                let mut known = lock(&shared.known);
                let mut missing = Vec::new();
                for ip in known.iter() {
                    if !actual.contains(ip) {
                        missing.push(*ip);
                    }
                }
                if !missing.is_empty() {
                    log_line(&format!(
                        "内核规则被外部清理，同步丢弃 {} 个内存缓存项",
                        missing.len()
                    ));
                    let mut managed = lock(&shared.managed);
                    for ip in missing {
                        known.remove(&ip);
                        managed.remove(&ip);
                    }
                }
            }
        }

        let ms = if cfg.interval_ms != 0 {
            cfg.interval_ms
        } else if shared.have_events.load(Ordering::Relaxed) {
            500
        } else {
            20
        };
        thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trace_syn_recv_v4() {
        let line = "nginx-1234 [002] .... 12345.678: inet_sock_set_state: family=AF_INET protocol=IPPROTO_TCP sport=443 dport=54321 saddr=10.0.0.1 daddr=203.0.113.5 saddrv6=::ffff:10.0.0.1 daddrv6=::ffff:203.0.113.5 oldstate=TCP_CLOSE newstate=TCP_SYN_RECV";
        assert_eq!(parse_trace_line(line), Some("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn parse_trace_ignores_established() {
        let line =
            "x [0] inet_sock_set_state: family=AF_INET daddr=1.2.3.4 newstate=TCP_ESTABLISHED";
        assert_eq!(parse_trace_line(line), None);
    }

    #[test]
    fn parse_conntrack_inbound() {
        let line = "    [NEW] tcp      6 120 SYN_SENT src=203.0.113.9 dst=10.0.0.2 sport=443 dport=12345 [UNREPLIED] src=10.0.0.2 dst=203.0.113.9 sport=12345 dport=443";
        let mut local = HashSet::new();
        local.insert("10.0.0.2".parse().unwrap());
        assert_eq!(
            peer_from_conntrack(line, &local),
            Some("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn parse_conntrack_outbound() {
        let line = "    [NEW] tcp      6 120 SYN_SENT src=10.0.0.2 dst=1.1.1.1 sport=9999 dport=443 [UNREPLIED] src=1.1.1.1 dst=10.0.0.2 sport=443 dport=9999";
        let mut local = HashSet::new();
        local.insert("10.0.0.2".parse().unwrap());
        assert_eq!(
            peer_from_conntrack(line, &local),
            Some("1.1.1.1".parse().unwrap())
        );
    }

    #[test]
    fn skip_rfc1918_cgnat_and_loopback() {
        assert!(is_lan_addr("10.1.2.3".parse().unwrap()));
        assert!(is_lan_addr("192.168.0.8".parse().unwrap()));
        assert!(is_lan_addr("172.16.5.1".parse().unwrap()));
        assert!(is_lan_addr("100.64.0.10".parse().unwrap()));
        assert!(is_lan_addr("fd12:3456::1".parse().unwrap()));
        assert!(!is_lan_addr("1.1.1.1".parse().unwrap()));
        assert!(is_always_skip("127.0.0.1".parse().unwrap()));
        assert!(is_always_skip("169.254.1.1".parse().unwrap()));
        assert!(is_always_skip("::1".parse().unwrap()));
        assert!(is_always_skip("fe80::1".parse().unwrap()));
    }

    #[test]
    fn on_link_subnet_is_lan() {
        let net = NetPrefix::parse("8.8.8.10/24").unwrap();
        assert!(net.is_subnet());
        assert!(net.contains("8.8.8.99".parse().unwrap()));
        assert!(!net.contains("8.8.9.1".parse().unwrap()));
        let host = NetPrefix::parse("8.8.8.10/32").unwrap();
        assert!(!host.is_subnet());
    }

    #[test]
    fn parse_ip_addr_show_collects_subnets() {
        let text = "\
2: eth0    inet 8.8.8.10/24 brd 8.8.8.255 scope global
2: eth0    inet6 2001:db8::1/64 scope global
3: lo      inet 127.0.0.1/8 scope host
";
        let mut ips = HashSet::new();
        let mut nets = Vec::new();
        parse_ip_addr_show(text, &mut ips, &mut nets);
        assert!(ips.contains(&"8.8.8.10".parse::<IpAddr>().unwrap()));
        assert!(nets.iter().any(|n| n.contains("8.8.8.50".parse().unwrap())));
    }

    #[test]
    fn parse_whitelist_cidrs_and_comments() {
        let nets = PrefixSet::from_prefixes(
            parse_whitelist_text("# clients\n203.0.113.5\n5.6.7.0/24  ;  8.8.8.8/32\n# skip\n")
                .unwrap(),
        );
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(in_nets(ip("203.0.113.5"), &nets));
        assert!(in_nets(ip("5.6.7.9"), &nets));
        assert!(!in_nets(ip("5.6.8.1"), &nets));
        assert!(in_nets(ip("8.8.8.8"), &nets));
        assert!(!in_nets(ip("1.1.1.1"), &nets));
    }

    #[test]
    fn invalid_whitelist_is_rejected() {
        assert!(parse_whitelist_text("1.2.3.4 bad-token").is_err());
    }

    #[test]
    fn whitelist_ranges_are_merged_and_fast() {
        let nets =
            PrefixSet::from_prefixes(parse_whitelist_text("10.0.0.0/25 10.0.0.128/25").unwrap());
        assert_eq!(
            nets.v4,
            vec![(
                u32::from(std::net::Ipv4Addr::new(10, 0, 0, 0)),
                u32::from(std::net::Ipv4Addr::new(10, 0, 0, 255))
            )]
        );
    }
}
