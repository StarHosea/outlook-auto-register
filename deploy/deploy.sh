#!/usr/bin/env bash
# 服务器端部署脚本 —— 由 GitHub Actions 通过 SSH 调用，也可手动执行。
#
#   bash deploy/deploy.sh
#
# 幂等：重复执行只会把代码对齐到 origin/$BRANCH 并重建容器，
# 不会动 data/ 与 accounts/ 里的运行期数据。
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/outlook-auto-register}"
BRANCH="${BRANCH:-master}"
HEALTH_URL="http://127.0.0.1:8890/api/ping"
HEALTH_RETRIES="${HEALTH_RETRIES:-45}"   # 首次构建后 Xvfb + Chromium 冷启动较慢，默认容忍 ~3min

log() { printf '[deploy %s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
die() { printf '[deploy ERROR] %s\n' "$*" >&2; exit 1; }

cd "$APP_DIR" || die "目录不存在: $APP_DIR"

# ── 0. 前置检查 ───────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "未安装 docker"
docker compose version >/dev/null 2>&1 || die "docker compose 不可用（可能是旧版 docker-compose）"
[ -f .env ] || die "缺少 .env（配置不入库，需在服务器上手工放置）"

git_dirty=$(git status --porcelain --untracked-files=no || true)
if [ -n "$git_dirty" ]; then
  # .env / data / accounts 都在 .gitignore 内，这里只可能是有 tracked 文件被改动。
  # 直接丢弃以保证部署结果 == origin/$BRANCH。
  log "检测到已跟踪文件的本地改动，将丢弃以对齐远端："
  printf '%s\n' "$git_dirty"
fi

# ── 1. 拉取代码 ───────────────────────────────────────────────
log "拉取 origin/$BRANCH ..."
git fetch --prune origin "$BRANCH"
git reset --hard "FETCH_HEAD"
git clean -fdq -e data -e accounts
log "当前版本: $(git rev-parse --short HEAD)  $(git log -1 --pretty=%s)"

# ── 2. 重建并重启容器 ─────────────────────────────────────────
log "docker compose up -d --build ..."
docker compose -f deploy/docker-compose.prod.yml up -d --build --remove-orphans

# ── 3. 清理悬空镜像（build 产生的旧层）─────────────────────────
log "清理悬空镜像 ..."
docker image prune -af --filter "until=168h" >/dev/null 2>&1 || true

# ── 4. 健康检查 ───────────────────────────────────────────────
log "等待健康检查 ${HEALTH_URL} ..."
for i in $(seq 1 "$HEALTH_RETRIES"); do
  if curl -fsS --max-time 4 "$HEALTH_URL" >/dev/null 2>&1; then
    log "部署成功（第 ${i} 次探测通过）"
    docker compose -f deploy/docker-compose.prod.yml ps
    exit 0
  fi
  # 中途容器就退出了就不用干等了，直接报错
  if [ "$(docker inspect -f '{{.State.Running}}' outlook-auto-register 2>/dev/null || echo false)" != "true" ]; then
    log "容器未运行，打最近 60 行日志："
    docker logs --tail 60 outlook-auto-register 2>&1 || true
    die "容器启动失败"
  fi
  sleep 4
done

log "健康检查超时，打最近 60 行日志："
docker logs --tail 60 outlook-auto-register 2>&1 || true
die "部署后 ${HEALTH_RETRIES} 次探测仍未通过"