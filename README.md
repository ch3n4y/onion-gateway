# onion-gateway

[![CI](https://github.com/ch3n4y/onion-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/ch3n4y/onion-gateway/actions/workflows/ci.yml)
[![Release](https://github.com/ch3n4y/onion-gateway/actions/workflows/release.yml/badge.svg)](https://github.com/ch3n4y/onion-gateway/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

把内网服务发布成 Tor v3 洋葱地址：**地址库（域名管理）+ 反代规则 + 前缀靓号**。
出口统一走 Caddy，前端 React，后端 Go/Gin，`docker compose` 一键部署。

```
                    Tor 网络
                       │  Host: <56字符>.onion
                   ┌───▼────┐   ADD_ONION / DEL_ONION (控制端口 9051)
                   │  tor   │◄──────────────┐
                   └───┬────┘               │
                       │ :8080 按 Host 路由 │
                   ┌───▼────┐   POST /load  │
                   │ caddy  │◄──────────────┤
                   └───┬────┘               │
                       │ 认证 / 限速 / 访问日志
              ┌────────▼────────┐      ┌────┴─────┐        ┌──────────┐
              │ 内网服务 (LAN)  │      │  panel   │◄───────┤   web    │◄── 浏览器 :19282
              └─────────────────┘      │  (API)   │  /api  │ (nginx)  │
                                       └──────────┘        └──────────┘
```

## 快速开始

```bash
cp .env.example .env      # 填 PANEL_PASSWORD；可选 SESSION_KEY=$(openssl rand -hex 32)
docker compose up -d --build
```

打开 `http://<host>:19282`。

## 三个页面

### 服务
一条规则 = 一个地址 + 一个内网目标。

- 新建时「自动分配新地址」，或从地址库里挑一个**未绑定**的地址。
- 编辑可改名 / 换目标 / 改 Basic Auth / 调限速，也能换绑或解绑（解绑后不再发布）。
- 目标输入框边输入边探测可达性（`POST /api/probe`）。
- **删除服务不会删地址**：地址退回地址库，随时能再绑给别的服务。

### 地址库
地址是独立实体：`56 字符 base32 + 私钥`，与任何服务解耦。

- 重命名、复制、解绑、删除（已绑定的不能直接删，先解绑）。
- 未绑定的地址不发布到 Tor。
- 来源分 `service` / `vanity` / `legacy`（旧版本自动迁移）。

### 靓号
后台并行搜索指定前缀。

- 前缀只能小写 `a-z` 与 `2-7`，最长 7 位；每多一位难度 ×32。
- 默认 `CPU-1` 核（上限 12），约 9 万 key/s（12 核），2 位前缀秒出。
- 同一时间只能跑一个任务；结果「加入地址库」才落盘（任务只在内存，重启即清空）。

## 为什么这样设计

- **地址来自密钥**：v3 地址 = `base32(PUBKEY | CHECKSUM | VERSION)`，无法指定。
  私钥是 tor 的 64 字节 **expanded key**（clamped scalar ‖ nonce prefix），
  公钥 `A = [a]B` 需要一次 edwards25519 点乘——纯 Go 就能离线造身份，
  不必把 mkp224o 编进容器。
- **不改 torrc**：全部走控制端口 `ADD_ONION ... Flags=Detach`。Detach 让服务在
  控制连接断开后继续跑，面板重启不丢；重启后用同一把私钥重放，地址不变。
- **Caddy 配置整体下发**：面板把状态渲染成完整 Caddy JSON，`POST /load` 推给
  admin API。每个地址一条 route（Host → 限速 → BasicAuth → reverse_proxy），
  末尾 404 兜底；`automatic_https.disable=true`（ACME 无法验证 `.onion`，否则
  会把洋葱域名泄露给 CA 并切成 HTTPS）。
- **限速按 onion 域名分桶**：Caddy 看到的客户端永远是 tor 容器 IP，按 IP 限速
  等于全局限速。
- **对账循环**：每 30s 拉一次 `GETINFO onions/detached`，与本地状态双向同步——
  已存在的认领，tor 重启丢掉的重新发布，多余的 DEL。重复 `ADD_ONION` 会触发
  tor 0.4.9 的 “private key collides” 断言并可能丢服务，所以必须认领而不是重放。

## 目录与端口

| 组件 | 说明 |
|---|---|
| `tor/` | 控制端口 9051，cookie 认证 |
| `caddy/` | xcaddy 构建，带 `rate_limit` 插件；admin 2019 仅内网 |
| 根目录 | Go/Gin API，`/data/services.json` 存地址库 + 服务，不发布端口 |
| `frontend/` | React + Vite，nginx 托管，`/api` 反代到 panel |

| 变量 | 默认 | 说明 |
|---|---|---|
| `PANEL_PASSWORD` | 必填 | 面板登录密码（启动时 bcrypt 哈希） |
| `PANEL_PASSWORD_HASH` | — | 直接给 bcrypt 哈希（优先） |
| `SESSION_KEY` | 随机 | hex ≥16 字节；不设则重启后需重新登录 |
| `PANEL_PORT` / `PANEL_BIND` | `19282` / `0.0.0.0` | web 容器发布端口 |
| `ONION_TARGET` | `caddy:8080` | tor 把所有洋葱流量转到这 |
| `VANITY_WORKERS` | `0`（自动） | 靓号并发数，0 = CPU-1（上限 12） |

## API

```
POST /api/login                     GET  /api/session
GET  /api/status                    POST /api/probe            {target}
GET  /api/services                  POST /api/services         {name,target,basic_user?,basic_pass?,rate_limit?,address_id?}
PATCH/DELETE /api/services/:id      DELETE 只删规则，地址保留
GET  /api/addresses                 PATCH /api/addresses/:id   {label}
DELETE /api/addresses/:id           已绑定时 409
POST /api/addresses/:id/unbind
GET  /api/vanity                    POST /api/vanity           {prefix,want}
POST /api/vanity/:id/stop           POST /api/vanity/:id/adopt {index}
```

## 墙内 / 受限网络

直连 Tor relay 被阻断、DNS 返回 fake-ip 时，需要三处调整（都不入库）：

1. `tor/torrc`：取消注释 `Socks5Proxy 127.0.0.1:7890`，指向你的 SOCKS5/HTTP 代理。
2. 新建 `docker-compose.override.yml`，给 tor 换真实 DNS：

   ```yaml
   services:
     tor:
       dns: [223.5.5.5, 119.29.29.29]
   ```

3. 可选，构建加速：`docker compose build --build-arg GOPROXY=https://goproxy.cn,direct`，
   前端在 `frontend/.npmrc` 取消注释 npmmirror 一行。

改完 `docker compose up -d tor`，几秒内 `Bootstrapped 100% (done)`。

## 发布与镜像

打 tag 触发 `.github/workflows/release.yml`：

```bash
git tag v0.2.0 && git push origin v0.2.0
```

- Release 附带 `linux/{amd64,arm64}`、`darwin/{amd64,arm64}` 的 panel 二进制，以及
  前端 `dist` 包；
- 多架构镜像推到 ghcr：`ghcr.io/ch3n4y/onion-gateway/panel` 与 `.../web`。

`ci.yml` 在每次 push/PR 跑 `go vet` + `go test -race` + 前端构建（push 时额外
`docker compose build`）。

## 安全须知

- 洋葱地址 = 全球可达的内网入口。建议每个服务都开 BasicAuth，必要时加限速。
- 面板只靠单用户密码；暴露在 LAN 时建议 `PANEL_BIND=127.0.0.1` 或加前置认证，
  **不要**把它本身发布成洋葱服务。
- `panel_data` 卷 = 所有洋葱私钥。丢了地址就永久丢了。
- tor 与 panel 容器以 root 运行（panel 需要读 cookie），都不发布端口。

## 开发

```bash
go test ./...                  # 假 tor 控制端口 + 假 caddy admin 的端到端断言
cd frontend && npm ci && npm run dev   # 5173，/api 反代到 127.0.0.1:8000
```

`go test` 覆盖：经 tor 验证的身份向量（地址派生 + 扩展密钥格式）、删服务保地址、
地址复用、靓号搜索/采纳/停止、`GETINFO` 两种回复格式、旧数据迁移、tor 重启后
自动重发。

## 已知限制

- 靓号任务只在内存；面板重启后历史任务消失（已采纳的地址不受影响）。
- 无 v3 client auth：访问控制靠 BasicAuth + 限速。
- 改 `target` 会重建洋葱（DEL + ADD），地址不变。
- tor 0.4.9 存在 collision 断言缺陷：若 tor 状态已损坏（服务既不在
  `onions/detached` 又无法 ADD），面板会打 `WARNING ... restart the tor container`，
  重启 tor 容器即可恢复。

## License

MIT
