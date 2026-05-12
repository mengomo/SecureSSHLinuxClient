# SSH 证书签发、加签与解析说明

这份文档整理了本次针对 OpenSSH `ssh-keygen` 证书签发流程的分析结论，重点回答以下问题：

- 证书签发入口在哪里
- `do_ca_sign()` 到底负责什么
- 真正的证书拼接和加签发生在哪里
- 被签名的对象和范围是什么
- `*-cert.pub` 是如何写出来的
- `ssh-keygen -L` 看到的人类可读输出和 `.pub` 里的 base64 是什么关系
- 这台机器和仓库里实际找到了哪些证书文件

## 背景说明

最开始读取本地 `source/ssh-keygen.c` 时，这个文件是空的；后续你更新了内容后，才能基于本地代码重新分析调用侧逻辑。

因此，这次结论来自两部分：

- 本地更新后的 `source/ssh-keygen.c`：负责说明 `ssh-keygen` 调用侧如何准备证书字段并触发签名
- OpenSSH 上游 `sshkey.c` / `authfile.c` / `sshkey.h`：负责说明真正的证书序列化、签名和落盘格式

## 先说结论

`do_ca_sign()` **不负责按字节拼接证书 blob**。

它的职责是：

1. 加载 CA key
2. 读取待签发公钥
3. 把命令行参数映射到 `struct sshkey_cert` 各字段
4. 准备 critical options / extensions
5. 写入证书里的 CA 公钥
6. 调用 `sshkey_certify()` / `sshkey_certify_custom()` 完成真正的序列化和签名

真正把这些字段串成 OpenSSH 证书二进制内容并完成签名的，是上游 `sshkey.c` 里的 `sshkey_certify_custom()`。

## 本地证书签发入口

在更新后的本地文件 `source/ssh-keygen.c` 中：

- `main()` 解析命令行参数
- 当使用 `-s` 指定 CA key 时，最终调用 `do_ca_sign()`

相关参数映射大致如下：

- `-s` → `ca_key_path`
- `-I` → `cert_key_id`
- `-n` → `cert_principals`
- `-V` → 有效期
- `-z` → serial
- `-h` → host certificate
- `-O` → certificate options
- `-U` → 优先通过 agent 签名

本地关键代码位置：

- `source/ssh-keygen.c:3167-3308`：参数解析
- `source/ssh-keygen.c:3457-3472`：确认签发分支并调用 `do_ca_sign()`
- `source/ssh-keygen.c:1601-1749`：`do_ca_sign()` 主流程

## `do_ca_sign()` 做了什么

### 1. 加载 CA key

`do_ca_sign()` 会根据运行方式选择 CA key 来源：

- PKCS#11
- ssh-agent
- 本地私钥文件

对应本地代码：`source/ssh-keygen.c:1616-1654`

如果是 RSA CA 且没有显式指定算法，它会默认用较新的 RSA 签名算法：

- `rsa-sha2-512`

对应本地代码：`source/ssh-keygen.c:1657-1665`

### 2. 准备扩展和限制项

在签发前，会先整理证书扩展和 critical options：

- `finalise_cert_exts()`：把命令行和默认选项收敛成扩展集合
- `prepare_options_buf()`：把这些扩展编码进 `sshbuf`

本地代码：

- `source/ssh-keygen.c:1504-1535`：`prepare_options_buf()`
- `source/ssh-keygen.c:1537-1560`：`finalise_cert_exts()`

### 3. 处理 principals

`cert_principals` 是逗号分隔字符串，`do_ca_sign()` 会把它拆成 `char **plist`，然后填入证书：

- `public->cert->nprincipals = n`
- `public->cert->principals = plist`

对应本地代码：`source/ssh-keygen.c:1669-1683, 1698-1699`

### 4. 把普通公钥升级成证书公钥

对于每个待签发公钥：

1. `sshkey_load_public()` 读入目标公钥
2. `sshkey_to_certified(public)` 把它从 plain key 升级成 cert key

对应本地代码：`source/ssh-keygen.c:1685-1694`

这一步之后，`public` 不再只是普通公钥，而是带有 `struct sshkey_cert` 的 certificate key。

### 5. 填充证书字段

`do_ca_sign()` 会把证书元数据填入 `public->cert`：

- `type`
- `serial`
- `key_id`
- `principals`
- `valid_after`
- `valid_before`
- `critical`
- `extensions`

对应本地代码：`source/ssh-keygen.c:1695-1703`

### 6. 把 CA 公钥放进证书

这一句非常关键：

- `sshkey_from_private(ca, &public->cert->signature_key)`

它会把 **CA 公钥**提取出来并写入证书对象。

注意：

- 证书里保存的是 **Signing CA 的公钥**
- 真正用于签名的是 **CA 私钥**

对应本地代码：`source/ssh-keygen.c:1704-1705`

### 7. 调用真正签名逻辑

最后根据运行路径调用：

- `sshkey_certify_custom(..., agent_signer, ...)`：通过 agent 签
- `sshkey_certify(...)`：普通直接签名路径

对应本地代码：`source/ssh-keygen.c:1707-1719`

## 证书结构是怎么来的

上游 `sshkey.h` 中，`struct sshkey_cert` 大致包含这些字段：

- `certblob`
- `type`
- `serial`
- `key_id`
- `nprincipals`
- `principals`
- `valid_after`
- `valid_before`
- `critical`
- `extensions`
- `signature_key`
- `signature_type`

可以把它理解成：

- 一份证书的“结构化内存表示”
- 加上一份最终序列化后的 `certblob`

其中：

- `do_ca_sign()` 主要是在填这些结构化字段
- `sshkey_certify_custom()` 负责把这些字段编码成 `certblob`

## 真正按字节拼接证书的地方

真正的字节级拼接发生在上游 `sshkey.c` 的：

- `sshkey_certify_custom()`

它会把 `k->cert` 中的内容按 OpenSSH certificate wire format 顺序写入：

1. 证书算法名，例如 `ssh-ed25519-cert-v01@openssh.com`
2. nonce
3. 被签发对象的原始公钥
4. `serial`
5. `cert type`（user / host）
6. `key_id`
7. principals 列表
8. `valid_after`
9. `valid_before`
10. critical options
11. extensions
12. reserved（空字段）
13. CA 公钥 blob

然后对这整段内容做签名，最后把 `signature` 追加到 `certblob` 末尾。

也就是说：

- `certblob` 前半段是“证书主体”
- 最后一段才是“证书签名”

## 被签名的对象和范围

被签名的不是某个单独字段，而是：

> 证书主体的完整序列化结果

也就是上面列出的 1 到 13 项。

注意几点：

- 被签发目标的**公钥本体**在签名范围内
- 证书元数据（serial、type、key_id、principals、validity、options、extensions）也都在签名范围内
- CA 公钥也在签名范围内
- **最终追加的 signature 字段本身不在签名范围内**

所以证书可以理解为：

- 证书主体
- 对证书主体的 CA 签名

## `do_ca_sign()` 如何“把这套东西搞出来”

如果按职责拆开看，过程是这样的：

### 调用侧：本地 `do_ca_sign()`

负责准备输入：

- 目标公钥
- CA key
- serial
- key id
- principals
- validity
- options / extensions
- CA 公钥

### 底层：上游 `sshkey_certify_custom()`

负责处理输出：

- 按证书格式序列化上述字段
- 生成 nonce
- 调 signer 用 CA 私钥签名
- 把签名追加进 `certblob`

所以它不是在 `do_ca_sign()` 里手写 `memcpy` 把所有字段拼起来，而是：

- `do_ca_sign()` 填结构体
- `sshkey_certify_custom()` 统一编码成证书 blob

## `*-cert.pub` 是如何写出来的

签名完成后，本地 `do_ca_sign()` 调用：

- `sshkey_save_public(public, out, comment)`

对应本地代码：`source/ssh-keygen.c:1722-1729`

而这个写文件链路在上游大致是：

1. `sshkey_save_public()`
2. `sshkey_write()`
3. `sshkey_format_text()`
4. `sshkey_to_base64()`
5. `sshkey_putb()`

其中最关键的一点是：

如果 key 是 certificate key，那么 `sshkey_putb()` 不会再重新拼装，而是直接使用：

- `key->cert->certblob`

也就是说，最终写入 `*.pub` 的第二段 base64，实际就是：

- 已经完成序列化并且已经包含签名的完整证书 blob

最终落盘文本大致长这样：

```text
<cert key type> <base64(certblob)> <comment>
```

例如：

```text
ssh-ed25519-cert-v01@openssh.com AAAA... comment
```

## `ssh-keygen -L` 输出和 base64 的关系

之前讨论过一段人类可读的证书信息，例如：

```text
id_ed25519-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:....
        Signing CA: ED25519 SHA256:....
        Key ID: "user_id"
        Serial: 0
        Valid: from 2023-10-27T10:00:00 to 2024-10-27T10:00:00
        Principals:
                username
        Critical Options: (none)
        Extensions:
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
```

这类输出不是原始 `.pub` 文件里的明文内容，而是：

1. 读取 `.pub` 文件中的第二段 base64
2. base64 解码成证书二进制 blob
3. 按 OpenSSH certificate 格式逐字段解析
4. 再格式化成人类可读文本

因此：

- `Type / Key ID / Serial / Valid / Principals / Extensions` 都是从证书 blob 中解析出来的
- `Signing CA` 是从证书中的 `signature_key` 取出 CA 公钥后，再格式化展示或计算指纹得到的
- `Critical Options: (none)` 也不是原文件明文写了 `(none)`，而是解析结果为空后的人类友好展示

## 一个容易混淆的点

`ssh-keygen.c` 里还有 `-Y sign` / `-Y verify` 那套签名逻辑，对应 `sig_sign()` / `sig_verify()`。

那一套是：

- 对任意数据或文件做签名/验签

不是：

- SSH certificate issuance

本次讨论的“证书签发”明确指的是：

- `main()` 参数解析
- `do_ca_sign()`
- `sshkey_certify()` / `sshkey_certify_custom()`

## 这台机器上找到了哪些证书

### 1. 真实系统常见位置

检查了这台机器上常见的运行路径：

- `~/.ssh/`
- `/etc/ssh/`

结果是：

- 两处都只有普通 key 和普通 `.pub`
- 没有现成的 `*-cert.pub`

例如：

- `~/.ssh/id_ed25519`
- `~/.ssh/id_ed25519.pub`
- `/etc/ssh/ssh_host_ed25519_key`
- `/etc/ssh/ssh_host_ed25519_key.pub`

但没有：

- `~/.ssh/id_ed25519-cert.pub`
- `/etc/ssh/ssh_host_ed25519_key-cert.pub`

### 2. 仓库中的样本证书

仓库里找到了一批 OpenSSH 自带测试证书样本，例如：

- `source/openssh-portable/regress/unittests/sshkey/testdata/ed25519_1-cert.pub`
- `source/openssh-portable/regress/unittests/sshkey/testdata/rsa_1-cert.pub`
- `source/openssh-portable/regress/unittests/sshkey/testdata/ecdsa_1-cert.pub`
- `source/openssh-portable/regress/misc/fuzz-harness/testdata/id_ed25519-cert.pub`

这些文件能直接看到 OpenSSH certificate 的文本格式，例如：

```text
ssh-ed25519-cert-v01@openssh.com AAAA... ED25519 test key #1
```

说明仓库里至少包含了已签好的证书样本，但它们是：

- 测试数据
- 不是当前机器在 `~/.ssh` 或 `/etc/ssh` 中正在使用的运行证书

## 总结

一句话总结整个链路：

1. `ssh-keygen` 通过 `main()` 解析 `-s/-I/-n/-V/-z/-O/-h/-U` 等参数
2. `do_ca_sign()` 加载 CA、读取目标公钥、填充 `struct sshkey_cert`
3. `sshkey_certify_custom()` 把证书字段按 OpenSSH 格式序列化到 `certblob`
4. 用 CA 私钥对证书主体签名
5. 把签名追加到 `certblob`
6. `sshkey_save_public()` 把完整 `certblob` 转成 base64，最终写成 `*-cert.pub`
7. `ssh-keygen -L` 再把这段 base64 解码并按字段解析成人类可读输出

如果后续还需要，可以继续在这份文档基础上补：

- `-I / -n / -V / -z / -O / -h / -U` 与证书字段的一一映射
- `sshkey_certify_custom()` 的字段顺序图
- `ssh-keygen -L` 输出和原始证书 blob 的逐字段对应关系
