#!/bin/bash

# =========================
# sing-box Hysteria2 保活脚本
# 最后更新时间: 2025.10.17
# 优化内存占用限制100MB
# =========================

export LANG=en_US.UTF-8
# 定义颜色
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
skyblue="\e[1;36m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033{0m"; }
skyblue() { echo -e "\e[1;36m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 定义常量
server_name="sing-box"
work_dir="/etc/sing-box"
config_dir="${work_dir}/config.json"
export hy2_port=${PORT:-$(shuf -i 1000-65000 -n 1)}

# 检查是否为root下运行
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# 检查命令是否存在函数
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查服务状态通用函数
check_service() {
    local service_name=$1
    local service_file=$2
    
    [[ ! -f "${service_file}" ]] && { red "not installed"; return 2; }
        
    if command_exists apk; then
        rc-service "${service_name}" status | grep -q "started" && green "running" || yellow "not running"
    else
        systemctl is-active "${service_name}" | grep -q "^active$" && green "running" || yellow "not running"
    fi
    return $?
}

# 检查sing-box状态
check_singbox() {
    check_service "sing-box" "${work_dir}/${server_name}"
}

# 检查argo状态
check_argo() {
    check_service "argo" "${work_dir}/argo"
}

# 检查看门狗状态
check_watchdog() {
    if command -v systemctl > /dev/null 2>&1; then
        systemctl is-active sing-box-watchdog >/dev/null 2>&1 && green "running" || yellow "not running"
    elif command -v rc-service > /dev/null 2>&1; then
        rc-service sing-box-watchdog status >/dev/null 2>&1 && green "running" || yellow "not running"
    else
        pgrep -f "watchdog.sh" >/dev/null && green "running" || yellow "not running"
    fi
}

#根据系统类型安装、卸载依赖
manage_packages() {
    if [ $# -lt 2 ]; then
        red "Unspecified package name or action" 
        return 1
    fi

    action=$1
    shift

    for package in "$@"; do
        if [ "$action" == "install" ]; then
            if command_exists "$package"; then
                green "${package} already installed"
                continue
            fi
            yellow "正在安装 ${package}..."
            if command_exists apt; then
                DEBIAN_FRONTEND=noninteractive apt install -y "$package"
            elif command_exists dnf; then
                dnf install -y "$package"
            elif command_exists yum; then
                yum install -y "$package"
            elif command_exists apk; then
                apk update
                apk add "$package"
            else
                red "Unknown system!"
                return 1
            fi
        elif [ "$action" == "uninstall" ]; then
            if ! command_exists "$package"; then
                yellow "${package} is not installed"
                continue
            fi
            yellow "正在卸载 ${package}..."
            if command_exists apt; then
                apt remove -y "$package" && apt autoremove -y
            elif command_exists dnf; then
                dnf remove -y "$package" && dnf autoremove -y
            elif command_exists yum; then
                yum remove -y "$package" && yum autoremove -y
            elif command_exists apk; then
                apk del "$package"
            else
                red "Unknown system!"
                return 1
            fi
        else
            red "Unknown action: $action"
            return 1
        fi
    done

    return 0
}

# 获取ip
get_realip() {
    ip=$(curl -4 -sm 2 ip.sb)
    ipv6() { curl -6 -sm 2 ip.sb; }
    if [ -z "$ip" ]; then
        echo "[$(ipv6)]"
    elif curl -4 -sm 2 http://ipinfo.io/org | grep -qE 'Cloudflare|UnReal|AEZA|Andrei'; then
        echo "[$(ipv6)]"
    else
        resp=$(curl -sm 8 "https://status.eooce.com/api/$ip" | jq -r '.status')
        if [ "$resp" = "Available" ]; then
            echo "$ip"
        else
            v6=$(ipv6)
            [ -n "$v6" ] && echo "[$v6]" || echo "$ip"
        fi
    fi
}

# 处理防火墙
allow_port() {
    has_ufw=0
    has_firewalld=0
    has_iptables=0
    has_ip6tables=0

    command_exists ufw && has_ufw=1
    command_exists firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1 && has_firewalld=1
    command_exists iptables && has_iptables=1
    command_exists ip6tables && has_ip6tables=1

    # 出站和基础规则
    [ "$has_ufw" -eq 1 ] && ufw --force default allow outgoing >/dev/null 2>&1
    [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --zone=public --set-target=ACCEPT >/dev/null 2>&1
    [ "$has_iptables" -eq 1 ] && {
        iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -i lo -j ACCEPT
        iptables -C INPUT -p icmp -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p icmp -j ACCEPT
        iptables -P FORWARD DROP 2>/dev/null || true
        iptables -P OUTPUT ACCEPT 2>/dev/null || true
    }
    [ "$has_ip6tables" -eq 1 ] && {
        ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -I INPUT 3 -i lo -j ACCEPT
        ip6tables -C INPUT -p icmp -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p icmp -j ACCEPT
        ip6tables -P FORWARD DROP 2>/dev/null || true
        ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    }

    # 入站
    for rule in "$@"; do
        port=${rule%/*}
        proto=${rule#*/}
        [ "$has_ufw" -eq 1 ] && ufw allow in ${port}/${proto} >/dev/null 2>&1
        [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --add-port=${port}/${proto} >/dev/null 2>&1
        [ "$has_iptables" -eq 1 ] && (iptables -C INPUT -p ${proto} --dport ${port} -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p ${proto} --dport ${port} -j ACCEPT)
        [ "$has_ip6tables" -eq 1 ] && (ip6tables -C INPUT -p ${proto} --dport ${port} -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p ${proto} --dport ${port} -j ACCEPT)
    done

    [ "$has_firewalld" -eq 1 ] && firewall-cmd --reload >/dev/null 2>&1

    # 规则持久化
    if command_exists rc-service 2>/dev/null; then
        [ "$has_iptables" -eq 1 ] && iptables-save > /etc/iptables/rules.v4 2>/dev/null
        [ "$has_ip6tables" -eq 1 ] && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
    else
        if ! command_exists netfilter-persistent; then
            manage_packages install iptables-persistent || yellow "请手动安装netfilter-persistent或保存iptables规则" 
            netfilter-persistent save >/dev/null 2>&1
        elif command_exists service; then
            service iptables save 2>/dev/null
            service ip6tables save 2>/dev/null
        fi
    fi
}

# 下载并安装 sing-box,cloudflared
install_singbox() {
    clear
    purple "正在安装sing-box中，请稍后..."
    # 判断系统架构
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64') ARCH='amd64' ;;
        'x86' | 'i686' | 'i386') ARCH='386' ;;
        'aarch64' | 'arm64') ARCH='arm64' ;;
        'armv7l') ARCH='armv7' ;;
        's390x') ARCH='s390x' ;;
        *) red "不支持的架构: ${ARCH_RAW}"; exit 1 ;;
    esac

    # 下载sing-box,cloudflared
    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
    curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"
    curl -sLo "${work_dir}/argo" "https://$ARCH.ssss.nyc.mn/bot"
    chown root:root ${work_dir} && chmod +x ${work_dir}/${server_name} ${work_dir}/argo

    # 生成随机密码
    uuid=$(cat /proc/sys/kernel/random/uuid)

    # 放行端口
    allow_port $hy2_port/udp > /dev/null 2>&1

    # 生成自签名证书
    openssl ecparam -genkey -name prime256v1 -out "${work_dir}/private.key"
    openssl req -new -x509 -days 3650 -key "${work_dir}/private.key" -out "${work_dir}/cert.pem" -subj "/CN=bing.com"
    
    # 检测网络类型并设置DNS策略
    dns_strategy=$(ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1 && echo "prefer_ipv4" || (ping -c 1 -W 3 2001:4860:4860::8888 >/dev/null 2>&1 && echo "prefer_ipv6" || echo "prefer_ipv4"))

   # 生成配置文件 - 只保留Hysteria2
cat > "${config_dir}" << EOF
{
  "log": {
    "disabled": false,
    "level": "error",
    "output": "$work_dir/sb.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "local",
        "strategy": "$dns_strategy"
      }
    ]
  },
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m"
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hysteria2",
      "listen": "::",
      "listen_port": $hy2_port,
      "users": [
        {
          "password": "$uuid"
        }
      ],
      "ignore_client_bandwidth": false,
      "masquerade": "https://bing.com",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "min_version": "1.3",
        "max_version": "1.3",
        "certificate_path": "$work_dir/cert.pem",
        "key_path": "$work_dir/private.key"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "final": "direct"
  }
}
EOF
}

# 添加进程保活看门狗服务
add_watchdog_service() {
    green "添加进程保活看门狗服务..."
    
    # 创建看门狗脚本
    cat > /etc/sing-box/watchdog.sh << 'EOF'
#!/bin/bash
# Sing-box 进程保活看门狗脚本

INTERVAL=30
MAX_RETRIES=3
LOG_FILE="/var/log/sing-box/watchdog.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

check_singbox() {
    if ! pgrep -x "sing-box" > /dev/null; then
        return 1
    fi
    
    # 检查端口监听
    if ! netstat -tulpn 2>/dev/null | grep -q "sing-box"; then
        return 1
    fi
    
    return 0
}

check_argo() {
    if ! pgrep -f "cloudflared" > /dev/null && ! pgrep -f "argo" > /dev/null; then
        return 1
    fi
    return 0
}

restart_singbox() {
    log "尝试重启 Sing-box 服务..."
    
    if command -v systemctl > /dev/null 2>&1; then
        systemctl restart sing-box
    elif command -v rc-service > /dev/null 2>&1; then
        rc-service sing-box restart
    else
        pkill -9 sing-box
        sleep 2
        /etc/sing-box/sing-box run -c /etc/sing-box/config.json &
    fi
    
    sleep 5
}

restart_argo() {
    log "尝试重启 Argo 服务..."
    
    if command -v systemctl > /dev/null 2>&1; then
        systemctl restart argo
    elif command -v rc-service > /dev/null 2>&1; then
        rc-service argo restart
    else
        pkill -f cloudflared
        pkill -f argo
        sleep 2
        /etc/sing-box/argo tunnel --url http://localhost:8001 --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1 &
    fi
    
    sleep 3
}

main() {
    log "Sing-box 看门狗服务启动"
    local singbox_retry=0
    local argo_retry=0
    
    while true; do
        # 检查 Sing-box
        if check_singbox; then
            if [ $singbox_retry -gt 0 ]; then
                log "Sing-box 服务恢复正常"
                singbox_retry=0
            fi
        else
            singbox_retry=$((singbox_retry + 1))
            log "Sing-box 服务异常，重启尝试 ($singbox_retry/$MAX_RETRIES)"
            
            if restart_singbox; then
                if check_singbox; then
                    log "Sing-box 重启成功"
                    singbox_retry=0
                fi
            fi
        fi
        
        # 检查 Argo
        if check_argo; then
            if [ $argo_retry -gt 0 ]; then
                log "Argo 服务恢复正常"
                argo_retry=0
            fi
        else
            argo_retry=$((argo_retry + 1))
            log "Argo 服务异常，重启尝试 ($argo_retry/$MAX_RETRIES)"
            
            if restart_argo; then
                if check_argo; then
                    log "Argo 重启成功"
                    argo_retry=0
                fi
            fi
        fi
        
        # 达到最大重试次数后暂停
        if [ $singbox_retry -ge $MAX_RETRIES ] || [ $argo_retry -ge $MAX_RETRIES ]; then
            log "达到最大重试次数，暂停监控 60 秒"
            sleep 60
            singbox_retry=0
            argo_retry=0
        fi
        
        sleep $INTERVAL
    done
}

# 捕获退出信号
trap "log '看门狗服务停止'; exit 0" TERM INT

main
EOF

    chmod +x /etc/sing-box/watchdog.sh
    
    # 创建看门狗服务文件
    if command -v systemctl > /dev/null 2>&1; then
        cat > /etc/systemd/system/sing-box-watchdog.service << EOF
[Unit]
Description=Sing-box Watchdog Service
After=network.target sing-box.service argo.service
Wants=sing-box.service argo.service

[Service]
Type=simple
User=root
ExecStart=/etc/sing-box/watchdog.sh
Restart=always
RestartSec=10
LimitNOFILE=65536
MemoryLimit=16M
CPUQuota=10%

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable sing-box-watchdog
        systemctl start sing-box-watchdog
        
    elif command -v rc-service > /dev/null 2>&1; then
        cat > /etc/init.d/sing-box-watchdog << 'EOF'
#!/sbin/openrc-run

name="sing-box-watchdog"
description="Sing-box Watchdog Service"
command="/etc/sing-box/watchdog.sh"
command_background=true
pidfile="/var/run/sing-box-watchdog.pid"

depend() {
    after sing-box argo
    need net
}

start_pre() {
    checkpath --directory --mode 755 /var/log/sing-box
}
EOF
        chmod +x /etc/init.d/sing-box-watchdog
        rc-update add sing-box-watchdog default
        rc-service sing-box-watchdog start
    fi
    
    green "进程保活看门狗服务已安装"
}

# 内存优化配置
optimize_memory() {
    green "应用内存优化配置..."
    
    # 优化内核参数
    cat >> /etc/sysctl.conf << EOF
# Memory optimization for sing-box
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
vm.swappiness = 10
EOF
    
    sysctl -p
    
    # 优化 Sing-box 配置以减少内存使用
    if [ -f "$config_dir" ] && command -v jq > /dev/null 2>&1; then
        jq '.log.level = "error"' "$config_dir" > "$config_dir.tmp" && mv "$config_dir.tmp" "$config_dir"
    fi
    
    green "内存优化完成"
}

# debian/ubuntu/centos 守护进程
main_systemd_services() {
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/etc/sing-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/etc/sing-box/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=5
LimitNOFILE=infinity
MemoryLimit=100M
CPUQuota=30%

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
NoNewPrivileges=yes
TimeoutStartSec=0
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --url http://localhost:8001 --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1"
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536
MemoryLimit=32M
CPUQuota=20%

[Install]
WantedBy=multi-user.target
EOF

    if [ -f /etc/centos-release ]; then
        yum install -y chrony
        systemctl start chronyd
        systemctl enable chronyd
        chronyc -a makestep
        yum update -y ca-certificates
        bash -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    fi
    systemctl daemon-reload 
    systemctl enable sing-box
    systemctl start sing-box
    systemctl enable argo
    systemctl start argo
}

# 适配alpine 守护进程
alpine_openrc_services() {
    cat > /etc/init.d/sing-box << 'EOF'
#!/sbin/openrc-run

description="sing-box service"
command="/etc/sing-box/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background=true
pidfile="/var/run/sing-box.pid"
EOF

    cat > /etc/init.d/argo << 'EOF'
#!/sbin/openrc-run

description="Cloudflare Tunnel"
command="/bin/sh"
command_args="-c '/etc/sing-box/argo tunnel --url http://localhost:8001 --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1'"
command_background=true
pidfile="/var/run/argo.pid"
EOF

    chmod +x /etc/init.d/sing-box
    chmod +x /etc/init.d/argo

    rc-update add sing-box default > /dev/null 2>&1
    rc-update add argo default > /dev/null 2>&1
}

# 生成节点信息
get_info() {  
  yellow "\nip检测中,请稍等...\n"
  server_ip=$(get_realip)
  clear
  isp=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g' || echo "vps")

  if [ -f "${work_dir}/argo.log" ]; then
      for i in {1..5}; do
          purple "第 $i 次尝试获取ArgoDoamin中..."
          argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log")
          [ -n "$argodomain" ] && break
          sleep 2
      done
  else
      restart_argo
      sleep 6
      argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log")
  fi

  green "\nArgoDomain：${purple}$argodomain${re}\n"

  # 只生成Hysteria2节点信息
  cat > ${work_dir}/node-info.txt << EOF
=== Hysteria2 节点信息 ===
服务器: ${server_ip}
端口: ${hy2_port}
密码: ${uuid}
SNI: www.bing.com
ALPN: h3
协议: udp
备注: ${isp}

节点链接:
hysteria2://${uuid}@${server_ip}:${hy2_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}
EOF

  echo ""
  green "=== Hysteria2 节点信息 ==="
  green "服务器: ${purple}${server_ip}${re}"
  green "端口: ${purple}${hy2_port}${re}"
  green "密码: ${purple}${uuid}${re}"
  green "SNI: ${purple}www.bing.com${re}"
  green "协议: ${purple}udp${re}"
  echo ""
  green "节点链接:"
  purple "hysteria2://${uuid}@${server_ip}:${hy2_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}"
  echo ""
}

# 通用服务管理函数
manage_service() {
    local service_name="$1"
    local action="$2"

    if [ -z "$service_name" ] || [ -z "$action" ]; then
        red "缺少服务名或操作参数\n"
        return 1
    fi
    
    local status=$(check_service "$service_name" 2>/dev/null)

    case "$action" in
        "start")
            if [ "$status" == "running" ]; then 
                yellow "${service_name} 正在运行\n"
                return 0
            elif [ "$status" == "not installed" ]; then 
                yellow "${service_name} 尚未安装!\n"
                return 1
            else 
                yellow "正在启动 ${service_name} 服务\n"
                if command_exists rc-service; then
                    rc-service "$service_name" start
                elif command_exists systemctl; then
                    systemctl daemon-reload
                    systemctl start "$service_name"
                fi
                
                if [ $? -eq 0 ]; then
                    green "${service_name} 服务已成功启动\n"
                    return 0
                else
                    red "${service_name} 服务启动失败\n"
                    return 1
                fi
            fi
            ;;
            
        "stop")
            if [ "$status" == "not installed" ]; then 
                yellow "${service_name} 尚未安装！\n"
                return 2
            elif [ "$status" == "not running" ]; then
                yellow "${service_name} 未运行\n"
                return 1
            else
                yellow "正在停止 ${service_name} 服务\n"
                if command_exists rc-service; then
                    rc-service "$service_name" stop
                elif command_exists systemctl; then
                    systemctl stop "$service_name"
                fi
                
                if [ $? -eq 0 ]; then
                    green "${service_name} 服务已成功停止\n"
                    return 0
                else
                    red "${service_name} 服务停止失败\n"
                    return 1
                fi
            fi
            ;;
            
        "restart")
            if [ "$status" == "not installed" ]; then
                yellow "${service_name} 尚未安装！\n"
                return 1
            else
                yellow "正在重启 ${service_name} 服务\n"
                if command_exists rc-service; then
                    rc-service "$service_name" restart
                elif command_exists systemctl; then
                    systemctl daemon-reload
                    systemctl restart "$service_name"
                fi
                
                if [ $? -eq 0 ]; then
                    green "${service_name} 服务已成功重启\n"
                    return 0
                else
                    red "${service_name} 服务重启失败\n"
                    return 1
                fi
            fi
            ;;
            
        *)
            red "无效的操作: $action\n"
            red "可用操作: start, stop, restart\n"
            return 1
            ;;
    esac
}

# 启动 sing-box
start_singbox() {
    manage_service "sing-box" "start"
}

# 停止 sing-box
stop_singbox() {
    manage_service "sing-box" "stop"
}

# 重启 sing-box
restart_singbox() {
    manage_service "sing-box" "restart"
}

# 启动 argo
start_argo() {
    manage_service "argo" "start"
}

# 停止 argo
stop_argo() {
    manage_service "argo" "stop"
}

# 重启 argo
restart_argo() {
    manage_service "argo" "restart"
}

# 看门狗服务管理
manage_watchdog() {
    clear
    echo ""
    green "=== 进程保活看门狗管理 ===\n"
    
    watchdog_status=$(check_watchdog)
    green "看门狗状态: $watchdog_status\n"
    
    green "1. 启动看门狗服务"
    skyblue "----------------"
    green "2. 停止看门狗服务" 
    skyblue "----------------"
    green "3. 重启看门狗服务"
    skyblue "----------------"
    green "4. 查看看门狗日志"
    skyblue "----------------"
    green "5. 内存优化配置"
    skyblue "----------------"
    purple "0. 返回主菜单"
    skyblue "-----------"
    reading "\n请输入选择: " choice
    
    case "${choice}" in
        1)
            if command -v systemctl > /dev/null 2>&1; then
                systemctl start sing-box-watchdog
            elif command -v rc-service > /dev/null 2>&1; then
                rc-service sing-box-watchdog start
            else
                nohup /etc/sing-box/watchdog.sh > /dev/null 2>&1 &
            fi
            green "看门狗服务已启动"
            ;;
        2)
            if command -v systemctl > /dev/null 2>&1; then
                systemctl stop sing-box-watchdog
            elif command -v rc-service > /dev/null 2>&1; then
                rc-service sing-box-watchdog stop
            else
                pkill -f "watchdog.sh"
            fi
            green "看门狗服务已停止"
            ;;
        3)
            if command -v systemctl > /dev/null 2>&1; then
                systemctl restart sing-box-watchdog
            elif command -v rc-service > /dev/null 2>&1; then
                rc-service sing-box-watchdog restart
            else
                pkill -f "watchdog.sh"
                nohup /etc/sing-box/watchdog.sh > /dev/null 2>&1 &
            fi
            green "看门狗服务已重启"
            ;;
        4)
            if [ -f "/var/log/sing-box/watchdog.log" ]; then
                echo -e "${green}最近看门狗日志：${re}"
                tail -20 /var/log/sing-box/watchdog.log
            else
                yellow "看门狗日志文件不存在"
            fi
            ;;
        5)
            optimize_memory
            ;;
        0) menu ;;
        *) red "无效的选项！" ;;
    esac
}

# 卸载 sing-box
uninstall_singbox() {
   reading "确定要卸载 sing-box 吗? (y/n): " choice
   case "${choice}" in
       y|Y)
           yellow "正在卸载 sing-box"
           if command_exists rc-service; then
                rc-service sing-box stop
                rc-service argo stop
                rc-service sing-box-watchdog stop 2>/dev/null || true
                rm /etc/init.d/sing-box /etc/init.d/argo /etc/init.d/sing-box-watchdog 2>/dev/null || true
                rc-update del sing-box default
                rc-update del argo default
                rc-update del sing-box-watchdog default 2>/dev/null || true
           else
                # 停止 sing-box和 argo 服务
                systemctl stop "${server_name}"
                systemctl stop argo
                systemctl stop sing-box-watchdog 2>/dev/null || true
                # 禁用 sing-box 服务
                systemctl disable "${server_name}"
                systemctl disable argo
                systemctl disable sing-box-watchdog 2>/dev/null || true

                # 重新加载 systemd
                systemctl daemon-reload || true
            fi
           # 删除配置文件和日志
           rm -rf "${work_dir}" || true
           rm -rf "${log_dir}" || true
           rm -rf /etc/systemd/system/sing-box.service /etc/systemd/system/argo.service /etc/systemd/system/sing-box-watchdog.service > /dev/null 2>&1
           rm -f /etc/sing-box/watchdog.sh > /dev/null 2>&1
           rm -f /var/log/sing-box/watchdog.log > /dev/null 2>&1
           
           green "\nsing-box 卸载成功\n\n" && exit 0
           ;;
       *)
           purple "已取消卸载操作\n\n"
           ;;
   esac
}

# 创建快捷指令
create_shortcut() {
  cat > "$work_dir/sb.sh" << EOF
#!/usr/bin/env bash

bash <(curl -Ls https://raw.githubusercontent.com/suouaki/agsb/main/sing-box.sh) \$1
EOF
  chmod +x "$work_dir/sb.sh"
  ln -sf "$work_dir/sb.sh" /usr/bin/sb
  if [ -s /usr/bin/sb ]; then
    green "\n快捷指令 sb 创建成功\n"
  else
    red "\n快捷指令创建失败\n"
  fi
}

# 适配alpine运行argo报错用户组和dns的问题
change_hosts() {
    sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
    sed -i '2s/.*/::1         localhost/' /etc/hosts
}

# 变更配置
change_config() {
    # 检查sing-box状态
    local singbox_status=$(check_singbox 2>/dev/null)
    local singbox_installed=$?
    
    if [ $singbox_installed -eq 2 ]; then
        yellow "sing-box 尚未安装！"
        sleep 1
        menu
        return
    fi
    
    clear
    echo ""
    green "=== 修改节点配置 ===\n"
    green "sing-box当前状态: $singbox_status\n"
    green "1. 修改Hysteria2端口"
    skyblue "------------"
    green "2. 修改Hysteria2密码"
    skyblue "------------"
    green "3. 添加Hysteria2端口跳跃"
    skyblue "------------"
    green "4. 删除Hysteria2端口跳跃"
    skyblue "------------"
    purple "0. 返回主菜单"
    skyblue "------------"
    reading "请输入选择: " choice
    case "${choice}" in
        1)
            reading "\n请输入Hysteria2端口 (回车跳过将使用随机端口): " new_port
            [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
            
            # 更新配置文件
            sed -i '/"type": "hysteria2"/,/"listen_port": [0-9]\+/ s/"listen_port": [0-9]\+/"listen_port": '"$new_port"'/' $config_dir
            
            # 重启服务
            restart_singbox
            
            # 放行新端口
            allow_port $new_port/udp > /dev/null 2>&1
            
            # 更新节点信息
            uuid=$(sed -n 's/.*"password": "\([^"]*\)".*/\1/p' $config_dir)
            server_ip=$(get_realip)
            isp=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g' || echo "vps")
            
            cat > ${work_dir}/node-info.txt << EOF
=== Hysteria2 节点信息 ===
服务器: ${server_ip}
端口: ${new_port}
密码: ${uuid}
SNI: www.bing.com
ALPN: h3
协议: udp
备注: ${isp}

节点链接:
hysteria2://${uuid}@${server_ip}:${new_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}
EOF

            green "\nHysteria2端口已修改为：${purple}${new_port}${re}\n"
            green "新的节点链接："
            purple "hysteria2://${uuid}@${server_ip}:${new_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}\n"
            ;;
            
        2)
            reading "\n请输入新的Hysteria2密码: " new_password
            [ -z "$new_password" ] && new_password=$(cat /proc/sys/kernel/random/uuid)
            
            # 更新配置文件
            sed -i '/"type": "hysteria2"/,/"password":/ s/"password": "[^"]*"/"password": "'"$new_password"'"/' $config_dir
            
            # 重启服务
            restart_singbox
            
            # 更新节点信息
            listen_port=$(sed -n '/"type": "hysteria2"/,/"listen_port": [0-9]*/ s/.*"listen_port": \([0-9]*\).*/\1/p' $config_dir)
            server_ip=$(get_realip)
            isp=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g' || echo "vps")
            
            cat > ${work_dir}/node-info.txt << EOF
=== Hysteria2 节点信息 ===
服务器: ${server_ip}
端口: ${listen_port}
密码: ${new_password}
SNI: www.bing.com
ALPN: h3
协议: udp
备注: ${isp}

节点链接:
hysteria2://${new_password}@${server_ip}:${listen_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}
EOF

            green "\nHysteria2密码已修改为：${purple}${new_password}${re}\n"
            green "新的节点链接："
            purple "hysteria2://${new_password}@${server_ip}:${listen_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}\n"
            ;;
            
        3)  
            purple "端口跳跃需确保跳跃区间的端口没有被占用，nat鸡请注意可用端口范围，否则可能造成节点不通\n"
            reading "请输入跳跃起始端口 (回车跳过将使用随机端口): " min_port
            [ -z "$min_port" ] && min_port=$(shuf -i 50000-65000 -n 1)
            yellow "你的起始端口为：$min_port"
            reading "\n请输入跳跃结束端口 (需大于起始端口): " max_port
            [ -z "$max_port" ] && max_port=$(($min_port + 100)) 
            yellow "你的结束端口为：$max_port\n"
            purple "正在安装依赖，并设置端口跳跃规则中，请稍等...\n"
            
            listen_port=$(sed -n '/"type": "hysteria2"/,/"listen_port": [0-9]*/ s/.*"listen_port": \([0-9]*\).*/\1/p' $config_dir)
            
            # 设置端口跳跃规则
            iptables -t nat -A PREROUTING -p udp --dport $min_port:$max_port -j DNAT --to-destination :$listen_port > /dev/null
            command -v ip6tables &> /dev/null && ip6tables -t nat -A PREROUTING -p udp --dport $min_port:$max_port -j DNAT --to-destination :$listen_port > /dev/null
            
            # 持久化规则
            if command_exists rc-service 2>/dev/null; then
                iptables-save > /etc/iptables/rules.v4
                command -v ip6tables &> /dev/null && ip6tables-save > /etc/iptables/rules.v6

                cat << 'EOF' > /etc/init.d/iptables
#!/sbin/openrc-run

depend() {
    need net
}

start() {
    [ -f /etc/iptables/rules.v4 ] && iptables-restore < /etc/iptables/rules.v4
    command -v ip6tables &> /dev/null && [ -f /etc/iptables/rules.v6 ] && ip6tables-restore < /etc/iptables/rules.v6
}
EOF

                chmod +x /etc/init.d/iptables && rc-update add iptables default && /etc/init.d/iptables start
            elif [ -f /etc/debian_version ]; then
                DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent > /dev/null 2>&1 && netfilter-persistent save > /dev/null 2>&1 
                systemctl enable netfilter-persistent > /dev/null 2>&1 && systemctl start netfilter-persistent > /dev/null 2>&1
            elif [ -f /etc/redhat-release ]; then
                manage_packages install iptables-services > /dev/null 2>&1 && service iptables save > /dev/null 2>&1
                systemctl enable iptables > /dev/null 2>&1 && systemctl start iptables > /dev/null 2>&1
                command -v ip6tables &> /dev/null && service ip6tables save > /dev/null 2>&1
                systemctl enable ip6tables > /dev/null 2>&1 && systemctl start ip6tables > /dev/null 2>&1
            else
                red "未知系统,请自行将跳跃端口转发到主端口" && exit 1
            fi            
            
            restart_singbox
            
            # 更新节点信息
            uuid=$(sed -n 's/.*"password": "\([^"]*\)".*/\1/p' $config_dir)
            server_ip=$(get_realip)
            isp=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g' || echo "vps")
            
            cat > ${work_dir}/node-info.txt << EOF
=== Hysteria2 节点信息 ===
服务器: ${server_ip}
端口: ${listen_port} (跳跃端口: ${min_port}-${max_port})
密码: ${uuid}
SNI: www.bing.com
ALPN: h3
协议: udp
备注: ${isp}

节点链接:
hysteria2://${uuid}@${server_ip}:${listen_port}/?peer=www.bing.com&insecure=1&alpn=h3&obfs=none&mport=${listen_port},${min_port}-${max_port}#${isp}
EOF

            green "\nHysteria2端口跳跃已开启,跳跃端口为：${purple}$min_port-$max_port${re}\n"
            green "新的节点链接："
            purple "hysteria2://${uuid}@${server_ip}:${listen_port}/?peer=www.bing.com&insecure=1&alpn=h3&obfs=none&mport=${listen_port},${min_port}-${max_port}#${isp}\n"
            ;;
            
        4)  
            # 清除端口跳跃规则
            iptables -t nat -F PREROUTING  > /dev/null 2>&1
            command -v ip6tables &> /dev/null && ip6tables -t nat -F PREROUTING  > /dev/null 2>&1
            
            # 清理持久化配置
            if command_exists rc-service 2>/dev/null; then
                rc-update del iptables default && rm -rf /etc/init.d/iptables 
            elif [ -f /etc/redhat-release ]; then
                netfilter-persistent save > /dev/null 2>&1
            elif [ -f /etc/redhat-release ]; then
                service iptables save > /dev/null 2>&1
                command -v ip6tables &> /dev/null && service ip6tables save > /dev/null 2>&1
            else
                manage_packages uninstall iptables ip6tables iptables-persistent iptables-service > /dev/null 2>&1
            fi
            
            # 更新节点信息
            uuid=$(sed -n 's/.*"password": "\([^"]*\)".*/\1/p' $config_dir)
            listen_port=$(sed -n '/"type": "hysteria2"/,/"listen_port": [0-9]*/ s/.*"listen_port": \([0-9]*\).*/\1/p' $config_dir)
            server_ip=$(get_realip)
            isp=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g' || echo "vps")
            
            cat > ${work_dir}/node-info.txt << EOF
=== Hysteria2 节点信息 ===
服务器: ${server_ip}
端口: ${listen_port}
密码: ${uuid}
SNI: www.bing.com
ALPN: h3
协议: udp
备注: ${isp}

节点链接:
hysteria2://${uuid}@${server_ip}:${listen_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}
EOF

            green "\n端口跳跃已删除\n"
            green "新的节点链接："
            purple "hysteria2://${uuid}@${server_ip}:${listen_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}\n"
            ;;
            
        0)  menu ;;
        *)  red "无效的选项！" ;; 
    esac
}

# 查看节点信息
check_nodes() {
    if [ ! -f "${work_dir}/node-info.txt" ]; then
        yellow "节点信息文件不存在，正在生成..."
        get_info
    fi
    
    echo ""
    cat ${work_dir}/node-info.txt
    echo ""
}

# Argo 管理
manage_argo() {
    # 检查Argo状态
    local argo_status=$(check_argo 2>/dev/null)
    local argo_installed=$?

    clear
    echo ""
    green "=== Argo 隧道管理 ===\n"
    green "Argo当前状态: $argo_status\n"
    green "1. 启动Argo服务"
    skyblue "------------"
    green "2. 停止Argo服务"
    skyblue "------------"
    green "3. 重启Argo服务"
    skyblue "------------"
    green "4. 添加Argo固定隧道"
    skyblue "----------------"
    green "5. 切换回Argo临时隧道"
    skyblue "------------------"
    green "6. 重新获取Argo临时域名"
    skyblue "-------------------"
    purple "0. 返回主菜单"
    skyblue "-----------"
    reading "\n请输入选择: " choice
    case "${choice}" in
        1)  start_argo ;;
        2)  stop_argo ;; 
        3)  clear
            if command_exists rc-service 2>/dev/null; then
                grep -Fq -- '--url http://localhost' /etc/init.d/argo && get_quick_tunnel && change_argo_domain || { green "\n当前使用固定隧道,无需获取临时域名"; sleep 2; menu; }
            else
                grep -q 'ExecStart=.*--url http://localhost' /etc/systemd/system/argo.service && get_quick_tunnel && change_argo_domain || { green "\n当前使用固定隧道,无需获取临时域名"; sleep 2; menu; }
            fi
         ;; 
        4)
            clear
            yellow "\n固定隧道可为json或token，固定隧道端口为8001，自行在cf后台设置\n\njson在f佬维护的站点里获取，获取地址：${purple}https://fscarmen.cloudflare.now.cc${re}\n"
            reading "\n请输入你的argo域名: " argo_domain
            ArgoDomain=$argo_domain
            reading "\n请输入你的argo密钥(token或json): " argo_auth
            if [[ $argo_auth =~ TunnelSecret ]]; then
                echo $argo_auth > ${work_dir}/tunnel.json
                cat > ${work_dir}/tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$argo_auth")
credentials-file: ${work_dir}/tunnel.json
protocol: http2
                                           
ingress:
  - hostname: $ArgoDomain
    service: http://localhost:8001
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF

                if command_exists rc-service 2>/dev/null; then
                    sed -i '/^command_args=/c\command_args="-c '\''/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1'\''"' /etc/init.d/argo
                else
                    sed -i '/^ExecStart=/c ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1"' /etc/systemd/system/argo.service
                fi
                restart_argo
                sleep 1 
                change_argo_domain

            elif [[ $argo_auth =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
                if command_exists rc-service 2>/dev/null; then
                    sed -i "/^command_args=/c\command_args=\"-c '/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token $argo_auth 2>&1'\"" /etc/init.d/argo
                else

                    sed -i '/^ExecStart=/c ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token '$argo_auth' 2>&1"' /etc/systemd/system/argo.service
                fi
                restart_argo
                sleep 1 
                change_argo_domain
            else
                yellow "你输入的argo域名或token不匹配，请重新输入"
                manage_argo            
            fi
            ;; 
        5)
            clear
            if command_exists rc-service 2>/dev/null; then
                alpine_openrc_services
            else
                main_systemd_services
            fi
            get_quick_tunnel
            change_argo_domain 
            ;; 

        6)  
            if command_exists rc-service 2>/dev/null; then
                if grep -Fq -- '--url http://localhost' "/etc/init.d/argo"; then
                    get_quick_tunnel
                    change_argo_domain 
                else
                    yellow "当前使用固定隧道，无法获取临时隧道"
                    sleep 2
                    menu
                fi
            else
                if grep -q 'ExecStart=.*--url http://localhost' "/etc/systemd/system/argo.service"; then
                    get_quick_tunnel
                    change_argo_domain 
                else
                    yellow "当前使用固定隧道，无法获取临时隧道"
                    sleep 2
                    menu
                fi
            fi 
            ;; 
        0)  menu ;; 
        *)  red "无效的选项！" ;;
    esac
}

# 获取argo临时隧道
get_quick_tunnel() {
    restart_argo
    yellow "获取临时argo域名中，请稍等...\n"
    sleep 3
    if [ -f /etc/sing-box/argo.log ]; then
      for i in {1..5}; do
          purple "第 $i 次尝试获取ArgoDoamin中..."
          get_argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "/etc/sing-box/argo.log")
          [ -n "$get_argodomain" ] && break
          sleep 2
      done
    else
      restart_argo
      sleep 6
      get_argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "/etc/sing-box/argo.log")
    fi
    green "ArgoDomain：${purple}$get_argodomain${re}\n"
    ArgoDomain=$get_argodomain
}

# 更新Argo域名到节点信息
change_argo_domain() {
    green "Argo域名已更新为: ${purple}$ArgoDomain${re}\n"
}

# singbox 管理
manage_singbox() {
    # 检查sing-box状态
    local singbox_status=$(check_singbox 2>/dev/null)
    local singbox_installed=$?
    
    clear
    echo ""
    green "=== sing-box 管理 ===\n"
    green "sing-box当前状态: $singbox_status\n"
    green "1. 启动sing-box服务"
    skyblue "-------------------"
    green "2. 停止sing-box服务"
    skyblue "-------------------"
    green "3. 重启sing-box服务"
    skyblue "-------------------"
    purple "0. 返回主菜单"
    skyblue "------------"
    reading "\n请输入选择: " choice
    case "${choice}" in
        1) start_singbox ;;  
        2) stop_singbox ;;
        3) restart_singbox ;;
        0) menu ;;
        *) red "无效的选项！" && sleep 1 && manage_singbox;;
    esac
}

# 主菜单
menu() {
   singbox_status=$(check_singbox 2>/dev/null)
   argo_status=$(check_argo 2>/dev/null)
   watchdog_status=$(check_watchdog)
   
   clear
   echo ""
   purple "=== sing-box Hysteria2 保活脚本 ===\n"
   purple "---Argo 状态: ${argo_status}"   
   purple "singbox 状态: ${singbox_status}"
   purple "看门狗状态: ${watchdog_status}\n"
   green "1. 安装sing-box"
   red "2. 卸载sing-box"
   echo "==============="
   green "3. sing-box管理"
   green "4. Argo隧道管理"
   green "5. 看门狗管理"
   echo  "==============="
   green  "6. 查看节点信息"
   green  "7. 修改节点配置"
   echo  "==============="
   purple "8. ssh综合工具箱"
   echo  "==============="
   red "0. 退出脚本"
   echo "==========="
   reading "请输入选择(0-8): " choice
   echo ""
}

# 捕获 Ctrl+C 退出信号
trap 'red "已取消操作"; exit' INT

# 主循环
while true; do
   menu
   case "${choice}" in
        1)  
            check_singbox &>/dev/null; check_singbox=$?
            if [ ${check_singbox} -eq 0 ]; then
                yellow "sing-box 已经安装！\n"
            else
                manage_packages install jq tar openssl lsof coreutils
                install_singbox
                if command_exists systemctl; then
                    main_systemd_services
                elif command_exists rc-update; then
                    alpine_openrc_services
                    change_hosts
                    rc-service sing-box restart
                    rc-service argo restart
                else
                    echo "Unsupported init system"
                    exit 1 
                fi

                sleep 5
                get_info
                create_shortcut
                # 添加进程保活看门狗
                add_watchdog_service
                # 应用内存优化
                optimize_memory
                green "\n✅ 安装完成！进程保活看门狗已启动\n"
            fi
           ;;
        2) uninstall_singbox ;;
        3) manage_singbox ;;
        4) manage_argo ;;
        5) manage_watchdog ;;
        6) check_nodes ;;
        7) change_config ;;
        8) 
           clear
           bash <(curl -Ls ssh_tool.eooce.com)
           ;;           
        0) exit 0 ;;
        *) red "无效的选项，请输入 0 到 8" ;;
   esac
   read -n 1 -s -r -p $'\033[1;91m按任意键返回...\033[0m'
done
