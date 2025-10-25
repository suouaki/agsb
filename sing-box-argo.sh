#!/bin/bash

# Sing-box Argo 隧道代理管理脚本
# 适配 Alpine, Ubuntu, Debian
# 优化内存占用版本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 系统变量
SING_BOX_VERSION="1.8.0"
SING_BOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-amd64.tar.gz"
CONFIG_DIR="/etc/sing-box"
LOG_DIR="/var/log/sing-box"
SERVICE_FILE=""
BINARY_PATH="/usr/local/bin/sing-box"
ARCH=""

# 检测系统
detect_system() {
    if [ -f /etc/alpine-release ]; then
        echo "alpine"
    elif [ -f /etc/debian_version ]; then
        if grep -q "Ubuntu" /etc/os-release; then
            echo "ubuntu"
        else
            echo "debian"
        fi
    else
        echo "unknown"
    fi
}

# 检测架构
detect_arch() {
    case $(uname -m) in
        x86_64) echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l) echo "armv7" ;;
        *) echo "amd64" ;;
    esac
}

# 日志函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_DIR/manager.log
}

info() { echo -e "${BLUE}[INFO]${NC} $1"; log "INFO: $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; log "SUCCESS: $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; log "WARNING: $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; log "ERROR: $1"; }

# 检查安装
check_installation() {
    if [ -f "$BINARY_PATH" ] || command -v sing-box > /dev/null 2>&1; then
        return 0
    else
        error "Sing-box 未安装"
        return 1
    fi
}

# 检查服务状态
check_status() {
    if pgrep -x "sing-box" > /dev/null; then
        echo "running"
    else
        echo "stopped"
    fi
}

# 安装依赖
install_dependencies() {
    local system=$(detect_system)
    info "安装系统依赖..."
    
    case $system in
        alpine)
            apk update
            apk add curl wget tar jq openssl net-tools
            ;;
        ubuntu|debian)
            apt update
            apt install -y curl wget tar jq openssl net-tools
            ;;
    esac
}

# 下载 Cloudflared
install_cloudflared() {
    info "安装 Cloudflared..."
    local arch=$(detect_arch)
    local url=""
    
    case $arch in
        amd64) url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64" ;;
        arm64) url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64" ;;
        armv7) url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm" ;;
    esac
    
    curl -L -o /usr/local/bin/cloudflared $url
    chmod +x /usr/local/bin/cloudflared
    
    # 创建 cloudflared 服务
    cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/cloudflared tunnel --config /etc/cloudflared/config.yml run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

# 安装 Sing-box
install_sing_box() {
    info "开始安装 Sing-box..."
    
    if check_installation 2>/dev/null; then
        warning "Sing-box 已安装"
        read -p "是否重新安装？(y/N): " reinstall
        if [ "$reinstall" != "y" ] && [ "$reinstall" != "Y" ]; then
            return
        fi
    fi
    
    install_dependencies
    
    # 下载 Sing-box
    cd /tmp
    local arch=$(detect_arch)
    local download_url="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${arch}.tar.gz"
    
    info "下载 Sing-box..."
    if ! curl -L -o sing-box.tar.gz "$download_url"; then
        error "下载失败"
        return 1
    fi
    
    # 解压安装
    tar -xzf sing-box.tar.gz
    cp sing-box-${SING_BOX_VERSION}-linux-${arch}/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # 创建目录
    mkdir -p $CONFIG_DIR $LOG_DIR /etc/cloudflared
    
    # 创建服务文件
    create_service_file
    
    # 设置权限
    chown -R nobody:nobody $CONFIG_DIR $LOG_DIR 2>/dev/null || true
    
    success "Sing-box 安装完成"
}

# 创建服务文件
create_service_file() {
    local system=$(detect_system)
    
    case $system in
        alpine)
            SERVICE_FILE="/etc/init.d/sing-box"
            cat > $SERVICE_FILE << 'EOF'
#!/sbin/openrc-run

name="sing-box"
description="Sing-box Proxy Service"
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_user="nobody"
command_background=true
output_log="/var/log/sing-box/service.log"
error_log="/var/log/sing-box/error.log"
pidfile="/run/sing-box.pid"

depend() {
    need net
    after cloudflared
}

start_pre() {
    checkpath --directory --owner nobody:nobody --mode 755 /var/log/sing-box
}

start_post() {
    sleep 2
    if ! pgrep -x "sing-box" > /dev/null; then
        eerror "Sing-box failed to start"
        return 1
    fi
    einfo "Sing-box started successfully"
}
EOF
            chmod +x $SERVICE_FILE
            ;;
        ubuntu|debian)
            SERVICE_FILE="/etc/systemd/system/sing-box.service"
            cat > $SERVICE_FILE << EOF
[Unit]
Description=Sing-box Proxy Service
After=network.target cloudflared.service
Wants=cloudflared.service

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=65536
MemoryLimit=64M
CPUQuota=50%

# 安全设置
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/sing-box /etc/sing-box

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            ;;
    esac
}

# 配置临时隧道
setup_temporary_tunnel() {
    info "配置临时 Argo 隧道..."
    
    # 安装 cloudflared
    install_cloudflared
    
    # 生成隧道配置
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local temp_dir=$(mktemp -d)
    
    # 启动临时隧道
    info "启动临时隧道..."
    /usr/local/bin/cloudflared tunnel --url http://localhost:8080 &
    local tunnel_pid=$!
    
    # 创建 Sing-box 配置
    create_sing_box_config "temporary" "localhost" "8080"
    
    # 启动 Sing-box
    start_sing_box
    
    success "临时隧道配置完成"
    info "隧道 PID: $tunnel_pid"
    info "使用命令 'kill $tunnel_pid' 停止隧道"
}

# 配置固定隧道
setup_permanent_tunnel() {
    info "配置固定 Argo 隧道..."
    
    read -p "输入隧道名称: " tunnel_name
    read -p "输入隧道密钥文件路径 (可选): " credential_file
    
    if [ -z "$tunnel_name" ]; then
        error "隧道名称不能为空"
        return 1
    fi
    
    # 安装 cloudflared
    install_cloudflared
    
    # 创建隧道配置
    mkdir -p /etc/cloudflared
    
    if [ -n "$credential_file" ] && [ -f "$credential_file" ]; then
        cp "$credential_file" /etc/cloudflared/credentials.json
    else
        info "请手动创建隧道凭证文件: /etc/cloudflared/credentials.json"
        info "使用命令: cloudflared tunnel create $tunnel_name"
    fi
    
    # 创建 cloudflared 配置
    cat > /etc/cloudflared/config.yml << EOF
tunnel: $tunnel_name
credentials-file: /etc/cloudflared/credentials.json
ingress:
  - hostname: your-domain.example.com
    service: http://localhost:8080
  - service: http_status:404
EOF
    
    info "请编辑 /etc/cloudflared/config.yml 配置您的域名"
    
    # 创建 Sing-box 配置
    create_sing_box_config "permanent" "localhost" "8080"
    
    success "固定隧道配置完成"
}

# 创建 Sing-box 配置（内存优化版）
create_sing_box_config() {
    local tunnel_type=$1
    local server=$2
    local port=$3
    
    info "创建内存优化的 Sing-box 配置..."
    
    cat > $CONFIG_DIR/config.json << EOF
{
  "log": {
    "level": "warn",
    "timestamp": true,
    "output": "/var/log/sing-box/sing-box.log"
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "https://1.1.1.1/dns-query",
        "detour": "direct"
      }
    ],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 2080,
      "sniff": true,
      "sniff_override_destination": true,
      "set_system_proxy": false
    },
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "singtun",
      "mtu": 9000,
      "stack": "mixed",
      "endpoint_independent_nat": true,
      "auto_route": true,
      "strict_route": false,
      "inet4_address": "172.19.0.1/30",
      "inet6_address": "fdfe:dcba:9876::1/126"
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
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "inbound": "tun-in",
        "outbound": "direct"
      }
    ],
    "auto_detect_interface": true,
    "final": "direct"
  }
}
EOF

    # 根据隧道类型添加代理出站
    if [ "$tunnel_type" = "temporary" ] || [ "$tunnel_type" = "permanent" ]; then
        add_proxy_outbound "$server" "$port"
    fi
    
    success "Sing-box 配置创建完成"
}

# 添加代理出站配置
add_proxy_outbound() {
    local server=$1
    local port=$2
    
    info "选择代理协议:"
    echo "1. SOCKS5"
    echo "2. HTTP"
    echo "3. Shadowsocks"
    echo "4. VMess"
    echo "5. 返回"
    read -p "请选择 [1-5]: " protocol_choice
    
    case $protocol_choice in
        1)
            configure_socks5 "$server" "$port"
            ;;
        2)
            configure_http "$server" "$port"
            ;;
        3)
            configure_shadowsocks "$server" "$port"
            ;;
        4)
            configure_vmess "$server" "$port"
            ;;
        *)
            return
            ;;
    esac
}

# 配置 SOCKS5 出站
configure_socks5() {
    local server=$1
    local port=$2
    
    read -p "输入用户名 (可选): " username
    read -p "输入密码 (可选): " password
    
    local outbound_config=$(cat << EOF
    {
      "type": "socks",
      "tag": "socks-out",
      "server": "$server",
      "server_port": $port,
      "version": "5",
      $( [ -n "$username" ] && echo "\"username\": \"$username\"," )
      $( [ -n "$password" ] && echo "\"password\": \"$password\"" )
    }
EOF
)
    
    update_outbound_config "$outbound_config"
}

# 配置 HTTP 出站
configure_http() {
    local server=$1
    local port=$2
    
    read -p "输入用户名 (可选): " username
    read -p "输入密码 (可选): " password
    
    local outbound_config=$(cat << EOF
    {
      "type": "http",
      "tag": "http-out",
      "server": "$server",
      "server_port": $port,
      $( [ -n "$username" ] && echo "\"username\": \"$username\"," )
      $( [ -n "$password" ] && echo "\"password\": \"$password\"" )
    }
EOF
)
    
    update_outbound_config "$outbound_config"
}

# 配置 Shadowsocks
configure_shadowsocks() {
    local server=$1
    local port=$2
    
    read -p "输入密码: " password
    read -p "输入加密方法 (默认: aes-256-gcm): " method
    method=${method:-"aes-256-gcm"}
    
    local outbound_config=$(cat << EOF
    {
      "type": "shadowsocks",
      "tag": "ss-out",
      "server": "$server",
      "server_port": $port,
      "method": "$method",
      "password": "$password"
    }
EOF
)
    
    update_outbound_config "$outbound_config"
}

# 配置 VMess
configure_vmess() {
    local server=$1
    local port=$2
    
    read -p "输入 UUID: " uuid
    read -p "输入 AlterId (默认: 0): " alter_id
    alter_id=${alter_id:-0}
    
    local outbound_config=$(cat << EOF
    {
      "type": "vmess",
      "tag": "vmess-out",
      "server": "$server",
      "server_port": $port,
      "uuid": "$uuid",
      "alter_id": $alter_id,
      "security": "auto"
    }
EOF
)
    
    update_outbound_config "$outbound_config"
}

# 更新出站配置
update_outbound_config() {
    local new_config=$1
    
    if ! command -v jq > /dev/null 2>&1; then
        error "jq 未安装，无法更新配置"
        return 1
    fi
    
    # 读取现有配置
    local current_config=$(cat $CONFIG_DIR/config.json)
    
    # 添加新的出站配置
    local updated_config=$(echo "$current_config" | jq \
        '.outbounds += ['"$new_config"'] | 
         .route.rules += [
           {
             "outbound": "socks-out",
             "geoip": ["private"]
           }
         ]')
    
    echo "$updated_config" > $CONFIG_DIR/config.json
    success "出站配置已更新"
}

# 启动服务
start_sing_box() {
    check_installation || return 1
    
    if [ "$(check_status)" = "running" ]; then
        warning "Sing-box 已在运行"
        return
    fi
    
    info "启动 Sing-box..."
    
    local system=$(detect_system)
    case $system in
        alpine)
            rc-service sing-box start
            ;;
        ubuntu|debian)
            systemctl start sing-box
            ;;
    esac
    
    sleep 3
    
    if [ "$(check_status)" = "running" ]; then
        success "Sing-box 启动成功"
    else
        error "Sing-box 启动失败"
    fi
}

# 停止服务
stop_sing_box() {
    check_installation || return 1
    
    if [ "$(check_status)" = "stopped" ]; then
        warning "Sing-box 已停止"
        return
    fi
    
    info "停止 Sing-box..."
    
    local system=$(detect_system)
    case $system in
        alpine)
            rc-service sing-box stop
            ;;
        ubuntu|debian)
            systemctl stop sing-box
            ;;
    esac
    
    # 停止 cloudflared
    pkill cloudflared 2>/dev/null || true
    systemctl stop cloudflared 2>/dev/null || true
    
    sleep 2
    
    if [ "$(check_status)" = "stopped" ]; then
        success "Sing-box 已停止"
    else
        error "Sing-box 停止失败"
    fi
}

# 重启服务
restart_sing_box() {
    check_installation || return 1
    
    info "重启 Sing-box..."
    stop_sing_box
    start_sing_box
}

# 设置开机自启
enable_autostart() {
    check_installation || return 1
    
    info "设置开机自启..."
    
    local system=$(detect_system)
    case $system in
        alpine)
            rc-update add sing-box default
            rc-update add cloudflared default 2>/dev/null || true
            ;;
        ubuntu|debian)
            systemctl enable sing-box
            systemctl enable cloudflared 2>/dev/null || true
            ;;
    esac
    
    success "开机自启已设置"
}

# 禁用开机自启
disable_autostart() {
    check_installation || return 1
    
    info "禁用开机自启..."
    
    local system=$(detect_system)
    case $system in
        alpine)
            rc-update del sing-box default
            rc-update del cloudflared default 2>/dev/null || true
            ;;
        ubuntu|debian)
            systemctl disable sing-box
            systemctl disable cloudflared 2>/dev/null || true
            ;;
    esac
    
    success "开机自启已禁用"
}

# 开启进程保护
enable_process_protection() {
    info "开启进程保护..."
    
    local system=$(detect_system)
    case $system in
        alpine)
            cat > /etc/init.d/sing-box-watchdog << 'EOF'
#!/sbin/openrc-run

name="sing-box-watchdog"
description="Sing-box Watchdog Service"
command="/usr/local/bin/sing-box-watchdog.sh"
command_background=true
pidfile="/run/sing-box-watchdog.pid"

depend() {
    after sing-box
}

start_pre() {
    checkpath --directory --mode 755 /var/log/sing-box
}
EOF
            chmod +x /etc/init.d/sing-box-watchdog
            ;;
        ubuntu|debian)
            # systemd 已经有内置的进程保护
            sed -i 's/Restart=always/Restart=always\nRestartSec=3\nStartLimitInterval=60\nStartLimitBurst=5/' $SERVICE_FILE
            systemctl daemon-reload
            ;;
    esac
    
    # 创建看门狗脚本
    create_watchdog_script
    
    success "进程保护已开启"
}

# 创建看门狗脚本
create_watchdog_script() {
    cat > /usr/local/bin/sing-box-watchdog.sh << 'EOF'
#!/bin/bash
# Sing-box 进程保护脚本

INTERVAL=30
MAX_RETRIES=3
LOG_FILE="/var/log/sing-box/watchdog.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

check_service() {
    if ! pgrep -x "sing-box" > /dev/null; then
        return 1
    fi
    
    # 检查端口监听
    if ! netstat -tulpn 2>/dev/null | grep -q "sing-box"; then
        return 1
    fi
    
    return 0
}

restart_service() {
    log "尝试重启 Sing-box 服务..."
    systemctl restart sing-box 2>/dev/null || \
    rc-service sing-box restart 2>/dev/null || \
    pkill sing-box && sleep 2 && /usr/local/bin/sing-box run -c /etc/sing-box/config.json &
    
    sleep 5
}

main() {
    log "Sing-box 看门狗启动"
    local retry_count=0
    
    while true; do
        if check_service; then
            if [ $retry_count -gt 0 ]; then
                log "服务恢复正常"
                retry_count=0
            fi
        else
            retry_count=$((retry_count + 1))
            log "服务异常，重启尝试 ($retry_count/$MAX_RETRIES)"
            
            if restart_service; then
                if check_service; then
                    log "重启成功"
                    retry_count=0
                fi
            fi
            
            if [ $retry_count -ge $MAX_RETRIES ]; then
                log "达到最大重试次数，暂停监控 60 秒"
                sleep 60
                retry_count=0
            fi
        fi
        
        sleep $INTERVAL
    done
}

trap "log '看门狗停止'; exit 0" TERM INT
main
EOF

    chmod +x /usr/local/bin/sing-box-watchdog.sh
}

# 查看配置
show_config() {
    check_installation || return 1
    
    info "当前配置信息:"
    echo ""
    
    if command -v jq > /dev/null 2>&1; then
        echo "=== 入站配置 ==="
        jq '.inbounds[] | {类型: .type, 端口: .listen_port, 监听: .listen}' $CONFIG_DIR/config.json 2>/dev/null || echo "无法解析配置"
        
        echo ""
        echo "=== 出站配置 ==="
        jq '.outbounds[] | select(.tag != "direct" and .tag != "block" and .tag != "dns-out") | {标签: .tag, 类型: .type, 服务器: .server, 端口: .server_port}' $CONFIG_DIR/config.json 2>/dev/null || echo "无代理出站配置"
    else
        cat $CONFIG_DIR/config.json
    fi
    
    echo ""
    echo "=== 使用说明 ==="
    echo "HTTP/SOCKS 代理: 127.0.0.1:2080"
    echo "TUN 模式: 自动配置"
    echo ""
    echo "测试命令:"
    echo "curl --proxy http://127.0.0.1:2080 http://ifconfig.me"
    echo "curl --socks5 127.0.0.1:2080 http://ifconfig.me"
}

# 暂停 Argo 服务
pause_argo() {
    info "暂停 Argo 隧道服务..."
    
    # 停止 cloudflared
    pkill cloudflared 2>/dev/null || true
    systemctl stop cloudflared 2>/dev/null || true
    
    # 更新 Sing-box 配置，移除隧道出站
    if command -v jq > /dev/null 2>&1; then
        jq 'del(.outbounds[] | select(.tag == "socks-out" or .tag == "http-out" or .tag == "ss-out" or .tag == "vmess-out"))' $CONFIG_DIR/config.json > $CONFIG_DIR/config.json.tmp
        mv $CONFIG_DIR/config.json.tmp $CONFIG_DIR/config.json
    fi
    
    restart_sing_box
    
    success "Argo 服务已暂停"
}

# 完全卸载
uninstall_sing_box() {
    check_installation || return 1
    
    warning "这将完全卸载 Sing-box 和所有相关配置"
    read -p "确定要卸载吗？(y/N): " confirm
    
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        # 停止服务
        stop_sing_box
        
        # 禁用自启
        disable_autostart
        
        # 移除文件
        info "移除文件..."
        rm -f /usr/local/bin/sing-box
        rm -f /usr/local/bin/cloudflared
        rm -rf $CONFIG_DIR
        rm -rf $LOG_DIR
        rm -rf /etc/cloudflared
        
        # 移除服务文件
        local system=$(detect_system)
        case $system in
            alpine)
                rm -f /etc/init.d/sing-box
                rm -f /etc/init.d/sing-box-watchdog
                rm -f /etc/init.d/cloudflared
                ;;
            ubuntu|debian)
                rm -f /etc/systemd/system/sing-box.service
                rm -f /etc/systemd/system/cloudflared.service
                systemctl daemon-reload
                ;;
        esac
        
        # 清理进程
        pkill -9 sing-box 2>/dev/null || true
        pkill -9 cloudflared 2>/dev/null || true
        
        # 清理网络接口
        ip link del singtun 2>/dev/null || true
        
        success "Sing-box 已完全卸载"
    else
        info "取消卸载"
    fi
}

# 内存优化
optimize_memory() {
    info "应用内存优化设置..."
    
    # 调整内核参数
    echo "net.core.rmem_max = 16777216" >> /etc/sysctl.conf
    echo "net.core.wmem_max = 16777216" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_rmem = 4096 87380 16777216" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_wmem = 4096 16384 16777216" >> /etc/sysctl.conf
    
    sysctl -p
    
    # 优化 Sing-box 配置
    if [ -f "$CONFIG_DIR/config.json" ]; then
        jq '.log.level = "error" | .dns.disabled = false' $CONFIG_DIR/config.json > $CONFIG_DIR/config.json.tmp
        mv $CONFIG_DIR/config.json.tmp $CONFIG_DIR/config.json
    fi
    
    success "内存优化完成"
}

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${CYAN}"
    echo "=========================================="
    echo "     Sing-box Argo 隧道代理管理脚本"
    echo "          内存优化版 - Alpine/Ubuntu/Debian"
    echo "=========================================="
    echo -e "${NC}"
    
    local status=$(check_status)
    local system=$(detect_system)
    
    echo -e "系统: ${YELLOW}$system${NC} | 状态: $( [ "$status" = "running" ] && echo -e "${GREEN}运行中${NC}" || echo -e "${RED}已停止${NC}" )"
    echo ""
    echo "1. 安装 Sing-box"
    echo "2. 配置临时 Argo 隧道"
    echo "3. 配置固定 Argo 隧道"
    echo "4. 启动 Sing-box 服务"
    echo "5. 停止 Sing-box 服务"
    echo "6. 重启 Sing-box 服务"
    echo "7. 设置开机自启"
    echo "8. 开启进程保护"
    echo "9. 查看代理配置"
    echo "10. 暂停 Argo 服务"
    echo "11. 内存优化"
    echo "12. 完全卸载"
    echo "0. 退出"
    echo ""
    echo -n "请选择操作 [0-12]: "
}

# 主循环
main() {
    # 检测系统
    local system=$(detect_system)
    if [ "$system" = "unknown" ]; then
                error "不支持的系统类型"
        exit 1
    fi
    
    # 创建必要目录
    mkdir -p $LOG_DIR
    
    while true; do
        show_main_menu
        read choice
        
        case $choice in
            1) install_sing_box ;;
            2) setup_temporary_tunnel ;;
            3) setup_permanent_tunnel ;;
            4) start_sing_box ;;
            5) stop_sing_box ;;
            6) restart_sing_box ;;
            7) enable_autostart ;;
            8) enable_process_protection ;;
            9) show_config ;;
            10) pause_argo ;;
            11) optimize_memory ;;
            12) uninstall_sing_box ;;
            0) 
                info "感谢使用！再见！"
                exit 0 
                ;;
            *) 
                error "无效选择，请重新输入"
                ;;
        esac
        
        echo ""
        read -p "按回车键继续..."
    done
}

# 脚本入口
if [ "$(id -u)" -ne 0 ]; then
    error "请使用 root 用户运行此脚本"
    echo "尝试使用 sudo 重新运行..."
    if command -v sudo > /dev/null 2>&1; then
        exec sudo "$0" "$@"
    else
        exit 1
    fi
fi

# 欢迎信息
echo -e "${GREEN}"
echo "=========================================="
echo "    Sing-box Argo 隧道代理管理脚本"
echo "          内存优化版本启动中..."
echo "=========================================="
echo -e "${NC}"
sleep 2

# 启动主循环
main
