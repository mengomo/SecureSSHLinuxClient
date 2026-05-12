# SSH CA 证书扩展与生命周期权限管理

## 概述

CA 在签发 SSH 用户证书时，会根据 ZF 产品生命周期阶段嵌入对应的 **扩展（Extensions）**、**关键选项（Critical Options）** 和 **生命周期 Principal**（`lc:<阶段名>`），从而实现按角色、按阶段的权限控制。

## ZF 产品生命周期 → SSH 权限配置

```
                    ┌──────────────┐
         ①dev       │              │  ①dev
      ┌────────────▶│   开发阶段    │◀────────────┐
      │             │              │              │
      │             └──────────────┘              │
      │                                           │
┌─────┴────────┐   ②prod    ┌──────────────────┐  │
│              │───────────▶│                  │──┘
│  ZF 生产阶段  │            │   现场运维阶段    │ ◀── 默认
│              │◀───────────│                  │
└──┬───────────┘   ④OEMprod └──┬───────────┬───┘
   │                           │           │
   │②prod    ┌──────────────┐  │③claims    │②prod
   └────────▶│              │◀─┘           │
             │ OEM 生产阶段  │    ┌─────────▼──────┐
             │              │    │                 │
             └──────────────┘    │   生命周期终止    │
                                 │                 │
             ┌──────────────┐    └─────────────────┘
             │  索赔/保修    │③claims
             │              │◀── 从现场运维阶段转入
             └──────────────┘
```

## 权限配置定义

| 配置名称 | 对应阶段 | 允许的 SSH 能力 | 关键选项 | 默认有效期 |
|---------|---------|---------------|---------|-----------|
| `zf_production` | ZF 生产 | 仅终端 (PTY) | `source-address`（可选） | 4 小时 |
| `development` | 开发 | 终端 + 端口转发 + Agent 转发 | `source-address`（可选） | 12 小时 |
| `oem_production` | OEM 生产 | 仅终端 | `source-address` + `force-command`（可选） | 4 小时 |
| **`field_operation`** | **现场运维（默认）** | **终端 + 端口转发** | **`source-address`（可选）** | **8 小时** |
| `claims_warranty` | 索赔/保修 | 仅终端 | `source-address` + `force-command`（可选） | 2 小时 |
| `end_of_life` | 生命周期终止 | 仅终端 | `source-address`（可选） | 1 小时 |
| `custom` | 自定义 | 调用方指定 | 调用方指定 | 调用方指定 |

## 诊断角色与权限矩阵

不同角色的 CA 操作员只能签发特定阶段的证书：

| 角色 | 可签发的配置（含对应 `lc:*` principal） |
|------|---------------------------------------|
| `dev` | `development`, `zf_production` |
| `prod` | `zf_production`, `oem_production`, `field_operation`, `end_of_life` |
| `claims` | `claims_warranty`, `field_operation` |
| `OEMprod` | `oem_production`, `field_operation` |
| `admin` | 全部配置 |

## SSH 扩展说明

证书中的扩展决定了用户在 SSH 会话中可以做什么：

| 扩展名称 | 功能 |
|---------|------|
| `permit-pty` | 允许分配交互式终端（没有此项则无法交互式登录） |
| `permit-port-forwarding` | 允许 SSH 隧道（`-L` / `-R` / `-D` 端口转发） |
| `permit-agent-forwarding` | 允许 `ssh-agent` 密钥代理转发到服务器 |
| `permit-X11-forwarding` | 允许 X11 图形界面转发 |
| `permit-user-rc` | 允许执行用户的 `~/.ssh/rc` 脚本 |

## 关键选项说明

关键选项是强制性限制，无法被用户绕过：

| 选项名称 | 功能 |
|---------|------|
| `force-command=<命令>` | 强制只能执行指定的命令，用户无法运行其他程序 |
| `source-address=<CIDR列表>` | 限制只有来自指定 IP 段的连接才能使用此证书 |
| `verify-required` | 要求 FIDO2 用户验证（触碰 + PIN） |

## 证书签发示例（ssh-keygen CLI）

CA 管理员使用 `ssh-keygen -s` 签发用户证书。注意每个证书同时包含 **用户 principal**
（对应 Linux 账户）和 **生命周期 principal**（`lc:<阶段名>`，用于标识所属阶段）。

### 现场运维（默认配置）

```bash
ssh-keygen -s /path/to/ssh_user_ca_key \
  -I "operator@device-001" \
  -n "rocky,lc:field_operation" \
  -V +8h \
  -O clear \
  -O extension:permit-pty \
  -O extension:permit-port-forwarding \
  id_ed25519.pub
```

### 开发阶段 + 限制来源 IP

```bash
ssh-keygen -s /path/to/ssh_user_ca_key \
  -I "dev@workstation" \
  -n "rocky,root,lc:development" \
  -V +12h \
  -O clear \
  -O extension:permit-pty \
  -O extension:permit-port-forwarding \
  -O extension:permit-agent-forwarding \
  -O critical:source-address=192.168.131.0/24 \
  id_ed25519.pub
```

### 索赔/保修 + 强制诊断工具

```bash
ssh-keygen -s /path/to/ssh_user_ca_key \
  -I "claims-tech@rma-unit-42" \
  -n "rocky,lc:claims_warranty" \
  -V +2h \
  -O clear \
  -O extension:permit-pty \
  -O critical:force-command=/usr/local/bin/diag-tool\ --read-only \
  -O critical:source-address=192.168.131.0/24 \
  id_ed25519.pub
```

### ZF 生产阶段

```bash
ssh-keygen -s /path/to/ssh_user_ca_key \
  -I "line-worker@factory-01" \
  -n "rocky,lc:zf_production" \
  -V +4h \
  -O clear \
  -O extension:permit-pty \
  id_ed25519.pub
```

### OEM 生产阶段

```bash
ssh-keygen -s /path/to/ssh_user_ca_key \
  -I "oem-integrator@oem-line-03" \
  -n "rocky,lc:oem_production" \
  -V +4h \
  -O clear \
  -O extension:permit-pty \
  id_ed25519.pub
```

### 生命周期终止

```bash
ssh-keygen -s /path/to/ssh_user_ca_key \
  -I "decom-tech@retired-device" \
  -n "rocky,lc:end_of_life" \
  -V +1h \
  -O clear \
  -O extension:permit-pty \
  id_ed25519.pub
```

## 证书检查示例

签发后可以用 `ssh-keygen -Lf` 查看证书内容：

```
$ ssh-keygen -Lf id_ed25519-cert.pub
id_ed25519-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Key ID: "dev@workstation"
        Serial: 1234567890
        Valid: from 2026-03-23T15:00:00 to 2026-03-24T03:00:00
        Principals:
                rocky
                root
                lc:development               ← 生命周期 principal
        Critical Options:                          ← 关键选项
                source-address  192.168.131.0/24
        Extensions:                                ← 扩展权限
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
```

## 服务器端生命周期访问控制

服务器通过 `AuthorizedPrincipalsCommand` 脚本（`authorized_principals_command.sh`）
和配置文件 `/etc/ssh/allowed_lifecycle_stages` 来控制允许哪些阶段的用户登录。

```
用户证书包含 principals: ["rocky", "lc:field_operation"]
                ↓
sshd 调用 AuthorizedPrincipalsCommand 脚本
                ↓
脚本检查：
  ① 证书是否包含目标用户名的 principal？ ✓ rocky 匹配
  ② lc:* principal 是否在允许列表中？     ✓ lc:field_operation 在列表中
                ↓
         两者都匹配 → 输出用户名 → sshd 放行
```

每台服务器按自身角色配置 `/etc/ssh/allowed_lifecycle_stages`：

```bash
# 产线服务器：
echo "lc:zf_production"  > /etc/ssh/allowed_lifecycle_stages
echo "lc:oem_production" >> /etc/ssh/allowed_lifecycle_stages

# 现场运维设备：
echo "lc:field_operation"  > /etc/ssh/allowed_lifecycle_stages
echo "lc:claims_warranty" >> /etc/ssh/allowed_lifecycle_stages

# 开发服务器：
echo "lc:development"     > /etc/ssh/allowed_lifecycle_stages
echo "lc:field_operation" >> /etc/ssh/allowed_lifecycle_stages
```

## sshd 与证书权限的交互关系

证书扩展和 sshd 配置是 **两层独立的限制**，取交集生效：

- 如果 **证书** 不含 `permit-port-forwarding`，即使 sshd 设了 `AllowTcpForwarding yes`，端口转发也 **不允许**（证书说了算）
- 如果 **sshd** 设了 `AllowTcpForwarding no`，即使证书包含 `permit-port-forwarding`，端口转发也 **不允许**（sshd 说了算）
- 实际权限 = 证书允许 **∩** sshd 允许

因此我们在 `sshd_config` 中设置 `AllowTcpForwarding yes` 和 `AllowAgentForwarding yes`，让 **证书配置成为唯一的权限控制点**。

## 证书生命周期

```
  签发 ──▶ 生效中 ──▶ 自然过期
               │
               ▼
           紧急吊销 (KRL)
```

1. **签发**：CA 根据生命周期配置签发证书，嵌入扩展、关键选项、Principal（含 `lc:*`）、有效期
2. **生效中**：证书在有效期内可用于认证，扩展权限控制会话能力
3. **自然过期**：到达有效期后，新连接被拒绝，无需人工清理
4. **紧急吊销**：如需立即吊销未过期证书，将序列号加入 SSH 密钥吊销列表 (KRL)：
   ```bash
   ssh-keygen -k -f /etc/ssh/revoked_keys -s /etc/ssh/trusted_user_ca_keys.pub -z <序列号> <证书文件>
   ```
   sshd_config 中已配置 `RevokedKeys /etc/ssh/revoked_keys`，加入 KRL 后立即生效。

## 会话强制终止器 — 证书过期自动断开

SSH 证书只控制 **认证阶段**（能不能连？），但已建立的会话不会在证书过期后自动断开。会话强制终止器解决了这个问题。

### 工作原理

1. `sshd_config` 中设置 `ExposeAuthInfo yes` → 每个会话都有一个临时文件保存认证证书
2. systemd 定时器每 60 秒运行一次 `ssh_session_enforcer.sh`
3. 脚本扫描 `/proc/*/environ` 找到 `SSH_AUTH_INFO_FILE`，提取证书，用 `ssh-keygen -Lf` 检查有效期
4. 过期的会话被终止（先发 `SIGHUP`，5 秒后发 `SIGTERM`）
5. 所有终止操作记录到 syslog，包含 `用户名`、`key_id` 和 `过期时间`

### 按配置自动区分

由于每个生命周期配置签发的证书 TTL 不同，终止器 **无需额外配置** 就能按阶段区分超时时间。`zf_production` 的证书（4 小时 TTL）在签发 4 小时后会被终止；`development` 的证书（12 小时 TTL）在 12 小时后终止。

### 部署步骤

```bash
# 1. 安装终止器脚本
sudo cp scripts/ssh_session_enforcer.sh /usr/local/bin/
sudo chmod 755 /usr/local/bin/ssh_session_enforcer.sh

# 2. 安装 systemd 服务单元
sudo cp systemd/ssh-session-enforcer.service /etc/systemd/system/
sudo cp systemd/ssh-session-enforcer.timer /etc/systemd/system/

# 3. 启用定时器
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-session-enforcer.timer

# 4. 验证运行状态
systemctl list-timers | grep ssh-session

# 5. 查看日志
journalctl -t ssh-session-enforcer -f
```
