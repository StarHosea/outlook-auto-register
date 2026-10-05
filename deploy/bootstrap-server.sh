#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# 一次性服务器初始化（幂等，可重复执行）
#
#   git clone 仓库 → 放 .env / 业务数据 → 签 TLS 证书 → 装 openresty
#   反代站点 → 首次 docker build + 起服务 → 冒烟验证
#
# 之后日常发布不需要再跑这个脚本，走 .github/workflows/deploy.yml 即可。
# ─────────────────────────────────────────────────────────────
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/outlook-auto-register}"
DOMAIN="${DOMAIN:-outlookreg.shuangdeng.space}"
REPO="${REPO:-https://github.com/StarHosea/outlook-auto-register.git}"
BRANCH="${BRANCH:-master}"
CONTAINER="${OPENRESTY_CONTAINER:-1Panel-openresty-NhRG}"
# ACME webroot。注意路径：
# openresty 容器把宿主机的 /opt/1panel/www 挂载成容器内的 /www，
# 所以站点配置里写的 `root /www/sites/acme` 对应宿主机的
# /opt/1panel/www/sites/acme。宿主机上另有一个真的 /www 目录，但它
# **没有**挂进容器——certbot 若写在那里，nginx 一律 404。
ACME_ROOT="/opt/1panel/www/sites/acme"
SSL_DIR_HOST="/opt/1panel/apps/openresty/openresty/conf/ssl/${DOMAIN}"
SSL_DIR_CONT="/usr/local/openresty/nginx/conf/ssl/${DOMAIN}"
SITE_CONF="/opt/1panel/www/conf.d/${DOMAIN}.conf"
STAGE="${STAGE:-/tmp/outlookreg-bootstrap}"

log()  { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 执行"

log "===== 1/7 拉取仓库 ====="
if [ -d "$APP_DIR/.git" ]; then
  log "已存在 git 仓库，fetch 并对齐 $BRANCH"
  cd "$APP_DIR"
  git fetch --prune origin "$BRANCH"
  git reset --hard "FETCH_HEAD"
else
  [ -e "$APP_DIR" ] && die "$APP_DIR 已存在但不是 git 仓库，请先移走"
  mkdir -p "$APP_DIR"
  git clone --depth 50 --branch "$BRANCH" "$REPO" "$APP_DIR"
  cd "$APP_DIR"
fi
mkdir -p data accounts backups

log "===== 2/7 放置配置与业务数据 ====="
# .env 不入库（含打码 API key / 代理 / 恢复邮箱配置），只在服务器本地留一份
if [ -f "$STAGE/.env" ]; then
  if [ -f "$APP_DIR/.env" ]; then
    cp -a "$APP_DIR/.env" "$APP_DIR/backups/.env.$(date +%Y%m%d%H%M%S)"
    warn "已有 .env，备份到 backups/ 后覆盖"
  fi
  install -m 600 "$STAGE/.env" "$APP_DIR/.env"
  log ".env 已就位（权限 600）"
else
  [ -f "$APP_DIR/.env" ] || die "缺少 .env"
fi

# 业务库：账号池 / 代理池 / 批次记录。只在服务器上没有库时才导入，
# 避免以后重跑把线上数据冲掉。
if [ -f "$STAGE/outlook.db" ] && [ ! -f "$APP_DIR/accounts/outlook.db" ]; then
  log "导入本地业务库 accounts/outlook.db ..."
  install -m 600 "$STAGE/outlook.db" "$APP_DIR/accounts/outlook.db"
else
  log "沿用服务器上已有的 accounts/outlook.db（不覆盖）"
fi
chmod 700 "$APP_DIR/data" "$APP_DIR/accounts" "$APP_DIR/backups"

log "===== 3/7 ACME 目录 + 临时证书 ====="
mkdir -p "$ACME_ROOT/.well-known/acme-challenge"
# 先用自签顶上，让 openresty 能通过 nginx -t 并起 HTTPS，
# 这样 certbot 的 HTTP-01 才有地方应答（自签不会覆盖 HTTP 校验）。
if [ ! -f "$SSL_DIR_HOST/privkey.pem" ]; then
  mkdir -p "$SSL_DIR_HOST"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
    -keyout "$SSL_DIR_HOST/privkey.pem" \
    -out "$SSL_DIR_HOST/fullchain.pem" \
    -subj "/CN=${DOMAIN}" >/dev/null 2>&1
  chmod 600 "$SSL_DIR_HOST/privkey.pem"
  log "已生成临时自签证书（3 天有效期，仅为引导用）"
fi

log "===== 4/7 安装 openresty 站点 ====="
install -m 644 "$STAGE/${DOMAIN}.conf" "$SITE_CONF"
docker exec "$CONTAINER" openresty -t 2>&1 | tail -3 || die "openresty 配置校验失败"
docker exec "$CONTAINER" openresty -s reload
log "站点已装载: $SITE_CONF"

log "===== 5/7 申请 Let's Encrypt 证书 ====="
# 自签还在位时 HTTP-01 已经通了，这里换真证书。
# Cloudflare 橙云会正常把 /.well-known/acme-challenge/ 回源，不受代理影响。
if docker exec "$CONTAINER" sh -c \
     "openssl x509 -in ${SSL_DIR_CONT}/fullchain.pem -noout -checkend 604800" >/dev/null 2>&1; then
  log "现有证书有效期 > 7 天，跳过签发"
else
  certbot certonly --non-interactive --agree-tos \
    --register-unsafely-without-email \
    --webroot -w "$ACME_ROOT" \
    -d "$DOMAIN" --keep-until-expiring \
    && log "certbot 签发成功" \
    || warn "certbot 失败，先用自签证书顶住（HTTPS 会有告警），可稍后手动重跑"
fi

if [ -d "/etc/letsencrypt/live/${DOMAIN}" ]; then
  install -m 644 "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$SSL_DIR_HOST/fullchain.pem"
  install -m 600 "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"  "$SSL_DIR_HOST/privkey.pem"
  docker exec "$CONTAINER" openresty -s reload
  log "真证书已装载并 reload"
fi

log "===== 6/7 构建并启动容器 ====="
cd "$APP_DIR"
bash deploy/deploy.sh

log "===== 7/7 冒烟验证 ====="
printf '  容器内 8890 : %s\n' "$(curl -fsS --max-time 5 http://127.0.0.1:8890/api/ping || echo FAIL)"
printf '  经 openresty : %s\n' \
  "$(curl -fsSk --max-time 8 --resolve "${DOMAIN}:443:127.0.0.1" "https://${DOMAIN}/api/ping" || echo FAIL)"

cat <<EOF

────────────────────────────────────────────────────────────
部署完成。

  地址     : https://${DOMAIN}
  目录     : ${APP_DIR}
  改代码后 : 直接 push 到 master，GitHub Actions 会自动部署
  手动部署 : ssh 到服务器执行  cd ${APP_DIR} && bash deploy/deploy.sh
  看日志   : docker logs -f outlook-auto-register
────────────────────────────────────────────────────────────
EOF