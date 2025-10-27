#!/bin/bash

# =========================
# sing-box vmess+Argo保活脚本
# 精简版 - 仅保留vmess协议和Argo代理
# 内存优化: sing-box 60MB, argo 30MB, 看门狗 20MB
# 最后更新时间: 2025.10.17
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
purple() { echo -e "\e[1;35m$1\033[0m"; }
skyblue() { echo -e "\e[1;36m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 定义常量
server_name="sing-box"
work_dir="/etc/sing-box"
config_dir="${work_dir}/config.json"
export vmess_port=${PORT:-$(shuf -i 1000-65000 -n 1)}
export CFIP=${CFIP:-'cf.877774.xyz'} 
export CFPORT=${CFPORT:-'443'} 

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

# 根据系统类型安装依赖
install_packages() {
    for package in "$@"; do
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

    command_exists ufw && has_ufw=1
    command_exists firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1 && has_firewalld=1
    command_exists iptables && has_iptables=1

    # 放行端口
    for rule in "$@"; do
        port=${rule%/*}
        proto=${rule#*/}
        [ "$has_ufw" -eq 1 ] && ufw allow in ${port}/${proto} >/dev/null 2>&1
        [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --add-port=${port}/${proto} >/dev/null 2>&1
        [ "$has_iptables" -eq 1 ] && (iptables -C INPUT -p ${proto} --dport ${port} -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p ${proto} --dport ${port} -j ACCEPT)
    done

    [ "$has_firewalld" -eq 1 ] && firewall-cmd --reload >/dev/null 2>&1
}

# 下载并安装 sing-box, cloudflared
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

    # 下载sing-box, cloudflared
    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
    curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"
    curl -sLo "${work_dir}/argo" "https://$ARCH.ssss.nyc.mn/bot"
    chown root:root ${work_dir} && chmod +x ${work_dir}/${server_name} ${work_dir}/argo

    # 生成UUID
    uuid=$(cat /proc/sys/kernel/random/uuid)

    # 放行端口
    allow_port $vmess_port/tcp > /dev/null 2>&1

    # 检测网络类型并设置DNS策略
    dns_strategy=$(ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1 && echo "prefer_ipv4" || (ping -c 1 -W 3 2001:4860:4860::8888 >/dev/null 2>&1 && echo "prefer_ipv6" || echo "prefer_ipv4"))

    # 生成精简配置文件 - 仅vmess协议
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
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "::",
      "listen_port": $vmess_port,
      "users": [
        {
          "uuid": "$uuid"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess-argo",
        "early_data_header_name": "Sec-WebSocket-Protocol"
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
    yellow "添加进程保活看门狗服务..."
    
    # 创建看门狗脚本
    cat > /etc/sing-box/watchdog.sh << 'EOF'
#!/bin/bash
# Sing-box 进程保活看门狗脚本 - 精简版

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
        /etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1 &
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
MemoryLimit=20M
CPUQuota=15%

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
    yellow "应用内存优化配置..."
    
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
MemoryLimit=60M
CPUQuota=40%

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
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1"
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536
MemoryLimit=30M
CPUQuota=25%

[Install]
WantedBy=multi-user.target
EOF

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
command_args="-c '/etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1'"
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

    # 生成vmess链接
    isp=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g' || echo "vps")
    VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"firefox\", \"allowlnsecure\": \"flase\"}"

    cat > ${work_dir}/url.txt <<EOF
vmess://$(echo "$VMESS" | base64 -w0)
EOF

    echo ""
    purple "VMESS节点链接:"
    cat ${work_dir}/url.txt
    echo ""
    yellow "\n=========================================================================================="
    green "\n节点信息已生成！复制上方vmess链接使用即可\n"
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
                # 停止服务
                systemctl stop "${server_name}"
                systemctl stop argo
                systemctl stop sing-box-watchdog 2>/dev/null || true
                # 禁用服务
                systemctl disable "${server_name}"
                systemctl disable argo
                systemctl disable sing-box-watchdog 2>/dev/null || true

                # 重新加载 systemd
                systemctl daemon-reload || true
            fi
           # 删除配置文件和日志
           rm -rf "${work_dir}" || true
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

bash <(curl -Ls https://raw.githubusercontent.com/suouaki/agsb/main/sing-boxs.sh) \$1
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
    green "1. 修改vmess端口"
    skyblue "------------"
    green "2. 修改UUID"
    skyblue "------------"
    green "3. 修改vmess-argo优选域名"
    skyblue "------------"
    purple "0. 返回主菜单"
    skyblue "------------"
    reading "请输入选择: " choice
    case "${choice}" in
        1)
            reading "\n请输入vmess端口 (回车跳过将使用随机端口): " new_port
            [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
            sed -i '/"type": "vmess"/,/listen_port/ s/"listen_port": [0-9]\+/"listen_port": '"$new_port"'/' $config_dir
            restart_singbox
            allow_port $new_port/tcp > /dev/null 2>&1
            
            if command_exists rc-service; then
                if grep -q "localhost:" /etc/init.d/argo; then
                    sed -i 's/localhost:[0-9]\{1,\}/localhost:'"$new_port"'/' /etc/init.d/argo
                    get_quick_tunnel
                    change_argo_domain 
                fi
            else
                if grep -q "localhost:" /etc/systemd/system/argo.service; then
                    sed -i 's/localhost:[0-9]\{1,\}/localhost:'"$new_port"'/' /etc/systemd/system/argo.service
                    get_quick_tunnel
                    change_argo_domain 
                fi
            fi

            if [ -f /etc/sing-box/tunnel.yml ]; then
                sed -i 's/localhost:[0-9]\{1,\}/localhost:'"$new_port"'/' /etc/sing-box/tunnel.yml
                restart_argo
            fi

            green "\nvmess端口已修改为：${purple}${new_port}${re}\n"
            ;;                    
        2)
            reading "\n请输入新的UUID: " new_uuid
            [ -z "$new_uuid" ] && new_uuid=$(cat /proc/sys/kernel/random/uuid)
            sed -i -E 's/"uuid": "([a-f0-9-]+)"/"uuid": "'"$new_uuid"'"/g' $config_dir

            restart_singbox
            get_quick_tunnel
            change_argo_domain
            green "\nUUID已修改为：${purple}${new_uuid}${re}\n"
            ;;
        3)  
            change_cfip ;;
        0)  menu ;;
        *)  read "无效的选项！" ;; 
    esac
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
            yellow "\n固定隧道可为json或token，固定隧道端口为$vmess_port，自行在cf后台设置\n\njson在f佬维护的站点里获取，获取地址：${purple}https://fscarmen.cloudflare.now.cc${re}\n"
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
    service: http://localhost:$vmess_port
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

# 更新Argo域名到配置
change_argo_domain() {
content=$(cat "$work_dir/url.txt")
vmess_url=$(grep -o 'vmess://[^ ]*' "$work_dir/url.txt")
vmess_prefix="vmess://"
encoded_vmess="${vmess_url#"$vmess_prefix"}"
decoded_vmess=$(echo "$encoded_vmess" | base64 --decode)
updated_vmess=$(echo "$decoded_vmess" | jq --arg new_domain "$ArgoDomain" '.host = $new_domain | .sni = $new_domain')
encoded_updated_vmess=$(echo "$updated_vmess" | base64 | tr -d '\n')
new_vmess_url="${vmess_prefix}${encoded_updated_vmess}"
new_content=$(echo "$content" | sed "s|$vmess_url|$new_vmess_url|")
echo "$new_content" > "$work_dir/url.txt"
green "vmess节点已更新\n"
purple "$new_vmess_url\n" 
}

# 查看节点信息
check_nodes() {
    if [ -f "$work_dir/url.txt" ]; then
        purple "VMESS节点链接:"
        cat "$work_dir/url.txt"
        echo ""
    else
        yellow "节点信息不存在，请先安装sing-box"
    fi
}

change_cfip() {
    clear
    yellow "修改vmess-argo优选域名\n"
    green "1: cf.090227.xyz  2: cf.877774.xyz  3: cf.877771.xyz  4: cdns.doon.eu.org  5: cf.zhetengsha.eu.org  6: time.is\n"
    reading "请输入你的优选域名或优选IP\n(请输入1至6选项,可输入域名:端口 或 IP:端口,直接回车默认使用1): " cfip_input

    if [ -z "$cfip_input" ]; then
        cfip="cf.090227.xyz"
        cfport="443"
    else
        case "$cfip_input" in
            "1")
                cfip="cf.090227.xyz"
                cfport="443"
                ;;
            "2")
                cfip="cf.877774.xyz"
                cfport="443"
                ;;
            "3")
                cfip="cf.877771.xyz"
                cfport="443"
                ;;
            "4")
                cfip="cdns.doon.eu.org"
                cfport="443"
                ;;
            "5")
                cfip="cf.zhetengsha.eu.org"
                cfport="443"
                ;;
            "6")
                cfip="time.is"
                cfport="443"
                ;;
            *)
                if [[ "$cfip_input" =~ : ]]; then
                    cfip=$(echo "$cfip_input" | cut -d':' -f1)
                    cfport=$(echo "$cfip_input" | cut -d':' -f2)
                else
                    cfip="$cfip_input"
                    cfport="443"
                fi
                ;;
        esac
    fi

content=$(cat "$work_dir/url.txt")
vmess_url=$(grep -o 'vmess://[^ ]*' "$work_dir/url.txt")
encoded_part="${vmess_url#vmess://}"
decoded_json=$(echo "$encoded_part" | base64 --decode 2>/dev/null)
updated_json=$(echo "$decoded_json" | jq --arg cfip "$cfip" --argjson cfport "$cfport" \
    '.add = $cfip | .port = $cfport')
new_encoded_part=$(echo "$updated_json" | base64 -w0)
new_vmess_url="vmess://$new_encoded_part"
new_content=$(echo "$content" | sed "s|$vmess_url|$new_vmess_url|")
echo "$new_content" > "$work_dir/url.txt"
green "\nvmess节点优选域名已更新为：${purple}${cfip}:${cfport}${re}\n"
purple "$new_vmess_url\n"
}

# 主菜单
menu() {
   singbox_status=$(check_singbox 2>/dev/null)
   argo_status=$(check_argo 2>/dev/null)
   watchdog_status=$(check_watchdog)
   
   clear
   echo ""
   purple "=== sing-box vmess+Argo保活脚本 ===\n"
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
   red "0. 退出脚本"
   echo "==========="
   reading "请输入选择(0-7): " choice
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
                install_packages jq curl
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
                green "内存占用限制: sing-box 60MB, argo 30MB, 看门狗 20MB\n"
            fi
           ;;
        2) uninstall_singbox ;;
        3) manage_singbox ;;
        4) manage_argo ;;
        5) manage_watchdog ;;
        6) check_nodes ;;
        7) change_config ;;
        0) exit 0 ;;
        *) red "无效的选项，请输入 0 到 7" ;;
   esac
   read -n 1 -s -r -p $'\033[1;91m按任意键返回...\033[0m'
done
