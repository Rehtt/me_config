#!/usr/bin/env bash
set -Eeuo pipefail

# 加密工作区，使用docker+luks

# =========================
# 加密工作区配置
# =========================

CRYPT_IMG="${CRYPT_IMG:-/secure/agent-work.img}"
CRYPT_NAME="${CRYPT_NAME:-agent_work_crypt}"
MOUNT_POINT="${MOUNT_POINT:-/secure/agent-work}"
CONTAINER_WORKDIR="${CONTAINER_WORKDIR:-/workspace}"

IMAGE="${IMAGE:-golang:1.26.4}"
CONTAINER_NAME="${CONTAINER_NAME:-go-agent-dev}"

HOST_UID="${HOST_UID:-${SUDO_UID:-1000}}"
HOST_GID="${HOST_GID:-${SUDO_GID:-1000}}"

CRYPT_SIZE="${CRYPT_SIZE:-50G}"

# =========================
# wgcf 出口配置
# =========================
# 指定宿主机 WireGuard / WARP 接口
WG_IFACE="${WG_IFACE:-wgcf}"

# Docker 内部 bridge 网络
NETWORK_NAME="${NETWORK_NAME:-agent_wg_net}"
BRIDGE_IFACE="${BRIDGE_IFACE:-br-agent-wg}"

# 容器专用网段，避免和你现有内网冲突
DOCKER_SUBNET="${DOCKER_SUBNET:-172.30.50.0/24}"
DOCKER_GATEWAY="${DOCKER_GATEWAY:-172.30.50.1}"
CONTAINER_IP="${CONTAINER_IP:-172.30.50.10}"

# 策略路由表
ROUTE_TABLE="${ROUTE_TABLE:-200}"
RULE_PRIORITY="${RULE_PRIORITY:-1200}"

# stop 时是否清理路由和 iptables
CLEAN_NET_ON_STOP="${CLEAN_NET_ON_STOP:-0}"

# =========================
# 工具函数
# =========================

log() {
  echo "[agent-workspace] $*"
}

die() {
  echo "[agent-workspace] ERROR: $*" >&2
  exit 1
}

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "请用 root 或 sudo 运行"
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"
}

check_deps() {
  need_cmd cryptsetup
  need_cmd mount
  need_cmd umount
  need_cmd findmnt
  need_cmd docker
  need_cmd ip
  need_cmd iptables
}

mapper_path() {
  echo "/dev/mapper/${CRYPT_NAME}"
}

is_unlocked() {
  cryptsetup status "$CRYPT_NAME" >/dev/null 2>&1
}

is_mounted() {
  findmnt -rn "$MOUNT_POINT" >/dev/null 2>&1
}

ensure_crypt_img_exists() {
  [[ -f "$CRYPT_IMG" ]] || die "加密文件不存在：$CRYPT_IMG。首次使用请先执行：sudo $0 init"
}

ensure_unlocked() {
  ensure_crypt_img_exists

  if is_unlocked; then
    log "加密区已解密：$(mapper_path)"
  else
    log "加密区未解密，开始解密：$CRYPT_IMG"
    cryptsetup open "$CRYPT_IMG" "$CRYPT_NAME"
    log "解密完成：$(mapper_path)"
  fi
}

ensure_mounted() {
  mkdir -p "$MOUNT_POINT"

  if is_mounted; then
    log "工作区已挂载：$MOUNT_POINT"
  else
    log "挂载工作区：$(mapper_path) -> $MOUNT_POINT"
    mount "$(mapper_path)" "$MOUNT_POINT"
    log "挂载完成：$MOUNT_POINT"
  fi

  mkdir -p \
    "$MOUNT_POINT/.home" \
    "$MOUNT_POINT/.cache/go-build" \
    "$MOUNT_POINT/.cache/gomod" \
    "$MOUNT_POINT/go"

  chown -R "$HOST_UID:$HOST_GID" "$MOUNT_POINT"
  chmod 700 "$MOUNT_POINT"
}

ensure_wgcf_exists() {
  ip link show "$WG_IFACE" >/dev/null 2>&1 || {
    echo
    echo "没有找到接口：$WG_IFACE"
    echo "请先确认 wgcf/WireGuard 已启动："
    echo "  ip addr show $WG_IFACE"
    echo "  ip route"
    echo
    die "wgcf 接口不存在"
  }

  if [[ "$(cat /sys/class/net/$WG_IFACE/operstate 2>/dev/null || true)" == "down" ]]; then
    log "警告：$WG_IFACE 当前状态可能是 down"
  fi
}

ensure_docker_network() {
  if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    log "Docker 网络已存在：$NETWORK_NAME"
  else
    log "创建 Docker bridge 网络：$NETWORK_NAME"
    docker network create \
      --driver bridge \
      --subnet "$DOCKER_SUBNET" \
      --gateway "$DOCKER_GATEWAY" \
      --opt "com.docker.network.bridge.name=$BRIDGE_IFACE" \
      "$NETWORK_NAME" >/dev/null
    log "Docker 网络创建完成：$NETWORK_NAME"
  fi
}

ensure_ip_forward() {
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

iptables_add_once() {
  local table="$1"
  shift

  if iptables -t "$table" -C "$@" 2>/dev/null; then
    return 0
  fi

  iptables -t "$table" -A "$@"
}

iptables_filter_add_once() {
  if iptables -C "$@" 2>/dev/null; then
    return 0
  fi

  iptables -A "$@"
}

ensure_wgcf_routing() {
  log "配置策略路由：$DOCKER_SUBNET -> $WG_IFACE"

  ip route replace default dev "$WG_IFACE" table "$ROUTE_TABLE"

  if ip -4 rule show | grep -Fq "from $DOCKER_SUBNET lookup $ROUTE_TABLE"; then
    log "策略路由规则已存在：from $DOCKER_SUBNET lookup $ROUTE_TABLE"
  else
    if ip -4 rule show | awk -F: '{print $1}' | grep -qx "$RULE_PRIORITY"; then
      log "优先级 $RULE_PRIORITY 已被占用，改用系统自动分配优先级"
      ip rule add from "$DOCKER_SUBNET" table "$ROUTE_TABLE"
    else
      ip rule add from "$DOCKER_SUBNET" table "$ROUTE_TABLE" priority "$RULE_PRIORITY"
    fi
  fi

  log "配置 NAT：$DOCKER_SUBNET 出口伪装到 $WG_IFACE"

  iptables_add_once nat POSTROUTING \
    -s "$DOCKER_SUBNET" \
    -o "$WG_IFACE" \
    -j MASQUERADE

  iptables_filter_add_once FORWARD \
    -i "$BRIDGE_IFACE" \
    -o "$WG_IFACE" \
    -j ACCEPT

  iptables_filter_add_once FORWARD \
    -i "$WG_IFACE" \
    -o "$BRIDGE_IFACE" \
    -m conntrack \
    --ctstate RELATED,ESTABLISHED \
    -j ACCEPT
}

cleanup_wgcf_routing() {
  log "清理 wgcf 策略路由和 NAT 规则"

  while ip rule show | grep -q "from ${DOCKER_SUBNET//\//\\/} lookup $ROUTE_TABLE"; do
    ip rule del from "$DOCKER_SUBNET" table "$ROUTE_TABLE" priority "$RULE_PRIORITY" 2>/dev/null || break
  done

  ip route flush table "$ROUTE_TABLE" 2>/dev/null || true

  iptables -t nat -D POSTROUTING \
    -s "$DOCKER_SUBNET" \
    -o "$WG_IFACE" \
    -j MASQUERADE 2>/dev/null || true

  iptables -D FORWARD \
    -i "$BRIDGE_IFACE" \
    -o "$WG_IFACE" \
    -j ACCEPT 2>/dev/null || true

  iptables -D FORWARD \
    -i "$WG_IFACE" \
    -o "$BRIDGE_IFACE" \
    -m conntrack \
    --ctstate RELATED,ESTABLISHED \
    -j ACCEPT 2>/dev/null || true
}

run_container() {
  log "启动并进入容器：$IMAGE"
  log "容器网络：$NETWORK_NAME"
  log "容器 IP：$CONTAINER_IP"
  log "出口接口：$WG_IFACE"
  log "工作区：$MOUNT_POINT -> $CONTAINER_WORKDIR"

  docker run --rm -it \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --ip "$CONTAINER_IP" \
    --dns 1.1.1.1 \
    --dns 1.0.0.1 \
    --user "$HOST_UID:$HOST_GID" \
    --workdir "$CONTAINER_WORKDIR" \
    --mount "type=bind,source=$MOUNT_POINT,target=$CONTAINER_WORKDIR" \
    --env "HOME=$CONTAINER_WORKDIR/.home" \
    --env "GOPATH=$CONTAINER_WORKDIR/go" \
    --env "GOCACHE=$CONTAINER_WORKDIR/.cache/go-build" \
    --env "GOMODCACHE=$CONTAINER_WORKDIR/.cache/gomod" \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    "$IMAGE" \
    bash
}

cmd_init() {
  need_root
  check_deps

  if [[ -e "$CRYPT_IMG" ]]; then
    die "文件已存在：$CRYPT_IMG。为了避免误删，不会覆盖。"
  fi

  mkdir -p "$(dirname "$CRYPT_IMG")"

  log "创建加密工作区文件：$CRYPT_IMG，大小：$CRYPT_SIZE"

  if [[ "$CRYPT_SIZE" =~ ^[0-9]+G$ ]]; then
    fallocate -l "$CRYPT_SIZE" "$CRYPT_IMG" 2>/dev/null || \
      dd if=/dev/zero of="$CRYPT_IMG" bs=1M count="$(( ${CRYPT_SIZE%G} * 1024 ))" status=progress
  else
    die "CRYPT_SIZE 当前只支持类似 50G、100G 这种格式"
  fi

  chmod 600 "$CRYPT_IMG"

  log "初始化 LUKS。接下来会要求输入 YES 和加密密码。"
  cryptsetup luksFormat "$CRYPT_IMG"

  log "打开加密区以创建文件系统。"
  cryptsetup open "$CRYPT_IMG" "$CRYPT_NAME"

  log "创建 ext4 文件系统。"
  mkfs.ext4 "$(mapper_path)"

  mkdir -p "$MOUNT_POINT"
  mount "$(mapper_path)" "$MOUNT_POINT"

  mkdir -p \
    "$MOUNT_POINT/.home" \
    "$MOUNT_POINT/.cache/go-build" \
    "$MOUNT_POINT/.cache/gomod" \
    "$MOUNT_POINT/go"

  chown -R "$HOST_UID:$HOST_GID" "$MOUNT_POINT"
  chmod 700 "$MOUNT_POINT"

  umount "$MOUNT_POINT"
  cryptsetup close "$CRYPT_NAME"

  log "初始化完成。以后使用：sudo $0 start"
}

cmd_start() {
  need_root
  check_deps

  ensure_unlocked
  ensure_mounted

  ensure_wgcf_exists
  ensure_docker_network
  ensure_ip_forward
  ensure_wgcf_routing

  run_container
}

cmd_stop() {
  need_root
  check_deps

  if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    log "停止正在运行的容器：$CONTAINER_NAME"
    docker stop "$CONTAINER_NAME" >/dev/null || true
  fi

  if [[ "$CLEAN_NET_ON_STOP" == "1" ]]; then
    cleanup_wgcf_routing

    if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
      log "删除 Docker 网络：$NETWORK_NAME"
      docker network rm "$NETWORK_NAME" >/dev/null || true
    fi
  fi

  if is_mounted; then
    log "卸载工作区：$MOUNT_POINT"
    umount "$MOUNT_POINT" || {
      echo
      echo "卸载失败，通常是还有进程占用工作区。你可以检查："
      echo "  lsof +f -- $MOUNT_POINT"
      echo "  fuser -vm $MOUNT_POINT"
      exit 1
    }
  else
    log "工作区未挂载：$MOUNT_POINT"
  fi

  if is_unlocked; then
    log "关闭 LUKS 加密区：$CRYPT_NAME"
    cryptsetup close "$CRYPT_NAME"
  else
    log "加密区未解密：$CRYPT_NAME"
  fi

  log "工作区已结束。"
}

cmd_status() {
  check_deps

  echo "加密文件:   $CRYPT_IMG"
  echo "Mapper:     $CRYPT_NAME"
  echo "挂载点:     $MOUNT_POINT"
  echo "镜像:       $IMAGE"
  echo
  echo "出口接口:   $WG_IFACE"
  echo "Docker网络: $NETWORK_NAME"
  echo "Bridge:     $BRIDGE_IFACE"
  echo "子网:       $DOCKER_SUBNET"
  echo "网关:       $DOCKER_GATEWAY"
  echo "容器 IP:    $CONTAINER_IP"
  echo "路由表:     $ROUTE_TABLE"
  echo

  if is_unlocked; then
    echo "LUKS:       unlocked"
  else
    echo "LUKS:       locked"
  fi

  if is_mounted; then
    echo "Mount:      mounted"
    findmnt "$MOUNT_POINT"
  else
    echo "Mount:      not mounted"
  fi

  if ip link show "$WG_IFACE" >/dev/null 2>&1; then
    echo "wgcf:       exists"
    ip addr show "$WG_IFACE" | sed 's/^/            /'
  else
    echo "wgcf:       not found"
  fi

  if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    echo "DockerNet:  exists"
  else
    echo "DockerNet:  not exists"
  fi

  echo
  echo "策略路由:"
  ip rule show | grep "$ROUTE_TABLE" || true
  ip route show table "$ROUTE_TABLE" || true

  echo
  echo "NAT 规则:"
  iptables -t nat -S POSTROUTING | grep "$DOCKER_SUBNET" || true
}

usage() {
  cat <<EOF
用法:
  sudo $0 init
  sudo $0 start
  sudo $0 stop
  sudo $0 status

默认配置:
  CRYPT_IMG=$CRYPT_IMG
  CRYPT_SIZE=$CRYPT_SIZE
  MOUNT_POINT=$MOUNT_POINT

  IMAGE=$IMAGE

  WG_IFACE=$WG_IFACE
  NETWORK_NAME=$NETWORK_NAME
  DOCKER_SUBNET=$DOCKER_SUBNET
  DOCKER_GATEWAY=$DOCKER_GATEWAY
  CONTAINER_IP=$CONTAINER_IP

示例:
  sudo $0 init
  sudo $0 start
  sudo $0 stop

指定 wgcf 接口名:
  sudo WG_IFACE=wgcf $0 start

如果你的 wgcf 接口名字不是 wgcf，比如 warp:
  sudo WG_IFACE=warp $0 start

停止时同时清理网络规则:
  sudo CLEAN_NET_ON_STOP=1 $0 stop
EOF
}

main() {
  case "${1:-}" in
    init)
      cmd_init
      ;;
    start)
      cmd_start
      ;;
    stop)
      cmd_stop
      ;;
    status)
      cmd_status
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
