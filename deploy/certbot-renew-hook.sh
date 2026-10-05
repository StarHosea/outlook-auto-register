#!/bin/sh
# certbot 续期 deploy hook —— 让 outlookreg.shuangdeng.space 的证书能自动生效。
#
# 为什么必须自己写：
#   certbot 续期只会把新证书写到 /etc/letsencrypt/live/<域名>/，而 openresty
#   读的是 /opt/1panel/apps/openresty/openresty/conf/ssl/<域名>/。不复制过去，
#   openresty 会一直拿旧证书；而 certbot 自带的 reload 钩子 reload 的是宿主
#   的 nginx 服务——这台机器上 nginx 服务是 failed、openresty 是 inactive，
#   那个钩子等于什么都没做。结果就是证书到期后站点静默过期。
#
# 装到：/etc/letsencrypt/renewal-hooks/deploy/outlookreg.sh
# 验证：sudo certbot renew --dry-run --cert-name outlookreg.shuangdeng.space
set -eu

DOMAIN=outlookreg.shuangdeng.space
certificate_dir="/etc/letsencrypt/live/${DOMAIN}"
openresty_certificate_dir="/opt/1panel/apps/openresty/openresty/conf/ssl/${DOMAIN}"

# certbot 会对 renewal-hooks/deploy 下的**所有**脚本触发（不区分域名），
# 所以别的域名续期时这个脚本也会被调用，必须在这里挡掉。
[ -d "$certificate_dir" ] || exit 0

install -d -m 0755 "$openresty_certificate_dir"
install -m 0644 "$certificate_dir/fullchain.pem" "$openresty_certificate_dir/fullchain.pem"
install -m 0600 "$certificate_dir/privkey.pem"  "$openresty_certificate_dir/privkey.pem"

# 先验配置再 reload，避免把整个站点 reload 成一堆坏配置（这台机器有 20+ 站点共用）
docker exec 1Panel-openresty-NhRG openresty -t >/dev/null
docker exec 1Panel-openresty-NhRG openresty -s reload >/dev/null