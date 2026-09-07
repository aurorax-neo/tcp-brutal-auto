#!/bin/sh
# 编译并安装 tcp-brutal-auto 到 /usr/local（需 root）
set -eu
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行: sudo $0" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "未找到 cargo。先安装 Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
  exit 1
fi

PREFIX="${PREFIX:-/usr/local}"
RATE="${RATE:-100}"

echo "编译 release ..."
cargo build --release

install -Dm755 target/release/tcp-brutal-auto "$PREFIX/bin/tcp-brutal-auto"
install -Dm644 tcp-brutal-auto.service /etc/systemd/system/tcp-brutal-auto.service

if [ "$RATE" != "100" ]; then
  mkdir -p /etc/systemd/system/tcp-brutal-auto.service.d
  printf '[Service]\nEnvironment=RATE=%s\n' "$RATE" \
    >/etc/systemd/system/tcp-brutal-auto.service.d/rate.conf
fi

systemctl daemon-reload
systemctl enable tcp-brutal-auto
systemctl restart tcp-brutal-auto
systemctl --no-pager --full status tcp-brutal-auto || true

echo
echo "已安装。日志: journalctl -u tcp-brutal-auto -f"
echo "改速率: systemctl edit tcp-brutal-auto   # Environment=RATE=500"
