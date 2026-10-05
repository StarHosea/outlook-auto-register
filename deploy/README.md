# 生产部署

线上环境：**https://outlookreg.shuangdeng.space**
服务器：`140.238.56.209`（Oracle Cloud Tokyo，Ubuntu 26.04，aarch64）
目录：`/opt/outlook-auto-register`

## 结构

| 文件 | 作用 |
|---|---|
| `docker-compose.prod.yml` | 生产编排。端口只绑 `127.0.0.1:8890`，公网入口统一走宿主机 openresty；带 healthcheck、日志轮转、`shm_size: 1gb`（Chromium 必需） |
| `deploy/deploy.sh` | 幂等部署脚本，`git reset --hard` 到 `origin/$BRANCH` + 重建容器 + 健康检查 |
| `deploy/bootstrap-server.sh` | **一次性**初始化：clone 仓库、放 `.env`、签证书、装反代、首次构建。日常发布不需要再跑 |
| `deploy/nginx/outlookreg.shuangdeng.space.conf` | 1Panel openresty 反代站点，落在 `/opt/1panel/www/conf.d/` |
| `deploy/certbot-renew-hook.sh` | 证书续期后把新证书同步进 openresty 目录并 reload |
| `.github/workflows/deploy.yml` | push 到 `master` 自动部署 |

## 日常发布

```bash
git push origin master
```

流水线会 SSH 到服务器执行 `deploy/deploy.sh`，部署完再打一次公网 `/api/ping` 冒烟。
想手动触发：`gh workflow run deploy.yml`。

服务器上直接跑也行：

```bash
ssh -i ~/.ssh/arm muhaoxing@140.238.56.209
cd /opt/outlook-auto-register && bash deploy/deploy.sh
docker logs -f outlook-auto-register
```

## GitHub 侧配置

| 类型 | 名称 | 值 |
|---|---|---|
| Actions **variable** | `DEPLOY_HOST` | `140.238.56.209` |
| Actions **variable** | `DEPLOY_USER` | `muhaoxing` |
| Actions **variable** | `DEPLOY_PATH` | `/opt/outlook-auto-register` |
| Actions **secret** | `DEPLOY_SSH_KEY` | `~/.ssh/arm` 私钥全文 |

流水线只信任 ed25519 这一把服务器主机密钥（指纹硬编码在 workflow 里），
不匹配直接失败——否则中间人只要在 `ssh-keyscan` 和 `ssh` 之间调包就能骗走部署私钥。

## 两个容易踩的坑

**compose 的 project directory 取第一个 compose 文件所在目录。**
所以 `docker-compose.prod.yml` 必须在仓库根目录。放 `deploy/` 下的话，
`./.env`、`./data`、`./accounts` 全会被解析成 `deploy/` 里的路径，直接报
`env file .../deploy/.env not found`。

**服务器上有两个 `/www`。** openresty 容器把宿主机的 `/opt/1panel/www`
挂载成容器内的 `/www`。站点配置里的 `root /www/sites/acme` 是**容器内**路径，
对应宿主机 `/opt/1panel/www/sites/acme`；宿主机上虽然也有个真的 `/www`，
但它没挂进容器。把校验文件写进宿主机 `/www/sites/acme`，nginx 一律 404。

## 证书

Let's Encrypt，webroot 模式，`certbot.timer` 每天跑一次（续期前有随机延迟，
最多约 8 分钟）。

续期只写 `/etc/letsencrypt/live/<域名>/`，而 openresty 读的是
`conf/ssl/<域名>/`，所以必须靠 `deploy/certbot-renew-hook.sh` 同步并 reload。
certbot 自带的钩子在这里没用——它 reload 的是宿主机 `nginx` 服务，
而这台机器上该服务是 `failed`、`openresty` 是 `inactive`。

改动证书相关配置后这样验证：

```bash
sudo certbot renew --dry-run --no-random-sleep-on-renew \
  --cert-name outlookreg.shuangdeng.space
```

## 数据

`data/` 与 `accounts/`（SQLite 业务库）都在 `.gitignore` 里，只存在于服务器本地，
重建镜像不受影响。`accounts/outlook.db` 是 SQLite 单文件，首次部署时从本地导入过一份。
备份直接拷这个文件即可（在线备份用 `sqlite3` 的 `.backup`，别直接 `cp` 正在写的库）。