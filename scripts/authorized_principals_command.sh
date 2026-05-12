#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# authorized_principals_command.sh
#
# 由 sshd 的 AuthorizedPrincipalsCommand 调用，用于基于证书 principal
# 实现生命周期感知的访问控制。
#
# 用法 (在 sshd_config 中配置):
#   AuthorizedPrincipalsCommand /usr/local/bin/authorized_principals_command.sh %u %t %k
#   AuthorizedPrincipalsCommandUser nobody
#
# 参数:
#   $1 = %u  目标 Linux 用户名 (如 rocky)
#   $2 = %t  密钥类型 (如 ssh-ed25519-cert-v01@openssh.com)
#   $3 = %k  Base64 编码的证书/公钥
#
# 逻辑:
#   1. 将 $2 $3 写入临时文件，用 ssh-keygen -Lf 解析证书
#   2. 提取证书中所有 principal
#   3. 检查是否包含目标用户名 ($1) — 用户身份验证
#   4. 检查是否包含 lc:* principal 且该阶段在服务器允许列表中 — 生命周期验证
#   5. 两者均匹配且仅包含一个 lc:* principal → 输出目标用户名 → sshd 放行
#      任一不匹配 → 无输出 → sshd 拒绝
#
# 服务器端配置:
#   /etc/ssh/allowed_lifecycle_stages  — 每行一个允许的 lc:* 值
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

LOG_TAG="ssh-principals-cmd"
ALLOWED_STAGES_FILE="/etc/ssh/allowed_lifecycle_stages"

log() { logger -t "$LOG_TAG" "$*"; }

# ── 参数检查 ──────────────────────────────────────────────────────────────────
TARGET_USER="${1:-}"
KEY_TYPE="${2:-}"
KEY_DATA="${3:-}"

if [[ -z "$TARGET_USER" || -z "$KEY_TYPE" || -z "$KEY_DATA" ]]; then
    log "ERROR: missing arguments (user=$TARGET_USER type=$KEY_TYPE)"
    exit 1
fi

# ── 检查是否为证书类型 ────────────────────────────────────────────────────────
# 如果不是证书 (不含 -cert-)，无法提取 principal，静默退出
if [[ "$KEY_TYPE" != *-cert-* ]]; then
    exit 0
fi

# ── 提取证书 principal ────────────────────────────────────────────────────────
TMP_CERT=$(mktemp /tmp/apc-cert-XXXXXX.pub)
trap 'rm -f "$TMP_CERT"' EXIT

echo "$KEY_TYPE $KEY_DATA" > "$TMP_CERT"

# 解析证书获取 principal 列表
CERT_INFO=$(ssh-keygen -Lf "$TMP_CERT" 2>/dev/null) || {
    log "WARN: failed to parse certificate for user=$TARGET_USER"
    exit 0
}

# 提取 Principals 段的内容 (每行一个 principal，缩进 16 空格)
PRINCIPALS=$(echo "$CERT_INFO" \
    | sed -n '/^ *Principals:$/,/^ *[A-Z]/{ /^ *Principals:$/d; /^ *[A-Z]/d; p; }' \
    | sed 's/^[[:space:]]*//')

if [[ -z "$PRINCIPALS" ]]; then
    log "WARN: no principals found in certificate for user=$TARGET_USER"
    exit 0
fi

# ── 检查 1: 用户 principal 是否匹配目标用户名 ─────────────────────────────────
USER_MATCH=false
while IFS= read -r principal; do
    if [[ "$principal" == "$TARGET_USER" ]]; then
        USER_MATCH=true
        break
    fi
done <<< "$PRINCIPALS"

if [[ "$USER_MATCH" != "true" ]]; then
    log "DENY: user=$TARGET_USER not in certificate principals"
    exit 0
fi

# ── 检查 2: 生命周期 principal 是否在允许列表中 ───────────────────────────────
# 正式环境缺省拒绝：如果 allowed_lifecycle_stages 文件不存在，则拒绝登录。
if [[ ! -f "$ALLOWED_STAGES_FILE" ]]; then
    log "DENY: user=$TARGET_USER missing lifecycle restriction file: $ALLOWED_STAGES_FILE"
    exit 0
fi

# 读取允许的阶段列表（忽略空行和 # 注释）
ALLOWED_STAGES=$(grep -v '^\s*#' "$ALLOWED_STAGES_FILE" 2>/dev/null \
    | grep -v '^\s*$' || true)

if [[ -z "$ALLOWED_STAGES" ]]; then
    log "WARN: allowed_lifecycle_stages file is empty, denying user=$TARGET_USER"
    exit 0
fi

# 提取证书中的 lc:* principal
LC_PRINCIPAL=""
LC_PRINCIPAL_COUNT=0
while IFS= read -r principal; do
    if [[ "$principal" == lc:* ]]; then
        LC_PRINCIPAL="$principal"
        LC_PRINCIPAL_COUNT=$((LC_PRINCIPAL_COUNT + 1))
    fi
done <<< "$PRINCIPALS"

if [[ -z "$LC_PRINCIPAL" ]]; then
    # 证书中没有 lc:* principal — 视为无生命周期标识
    # 根据策略可以拒绝或放行。这里选择拒绝。
    log "DENY: user=$TARGET_USER certificate has no lifecycle principal (lc:*)"
    exit 0
fi

if (( LC_PRINCIPAL_COUNT > 1 )); then
    log "DENY: user=$TARGET_USER certificate has multiple lifecycle principals"
    exit 0
fi

# 检查 lc:* principal 是否在允许列表中
STAGE_MATCH=false
while IFS= read -r allowed; do
    if [[ "$LC_PRINCIPAL" == "$allowed" ]]; then
        STAGE_MATCH=true
        break
    fi
done <<< "$ALLOWED_STAGES"

if [[ "$STAGE_MATCH" != "true" ]]; then
    log "DENY: user=$TARGET_USER lifecycle=$LC_PRINCIPAL not in allowed stages"
    exit 0
fi

# ── 全部通过 → 输出用户名，sshd 放行 ─────────────────────────────────────────
log "ALLOW: user=$TARGET_USER lifecycle=$LC_PRINCIPAL"
echo "$TARGET_USER"
