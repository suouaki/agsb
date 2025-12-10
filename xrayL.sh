#!/bin/bash

# 脚本名称: xrayL.sh
# 功能: Xray 代理服务器管理脚本
# 支持: macOS, Linux (Ubuntu/Debian/CentOS/RHEL/Alpine)
# 支持: SOCKS5 和 VMESS+WebSocket 协议
# 支持: IPv4 和 IPv6

DEFAULT_START_PORT=20000                         #默认起始端口
DEFAULT_END_PORT=20005                           #默认结束端口（创建端口范围）
DEFAULT_SOCKS_USERNAME="userb"                   #默认socks账号
DEFAULT_SOCKS_PASSWORD="passwordb"               #默认socks密码
DEFAULT_WS_PATH="/ws"                            #默认ws路径
DEFAULT_UUID=""                                  #将在初始化时生成
CONFIG_FILE="/etc/xrayL/config.toml"             #配置文件路径
SERVICE_NAME="xrayL"                             #服务名称
INSTALL_PATH="/usr/local/bin/xrayL"              #安装路径
SCRIPT_NAME="xrayL.sh"                           #脚本名称
SS_ALIAS="ss"                                    #快捷键别名
SUBSCRIPTION_FILE="/etc/xrayL/subscription.txt"  #订阅文件路径
SUBSCRIPTION_URL_FILE="/etc/xrayL/subscription_url.txt" #订阅URL保存路径

# 检测操作系统
OS_TYPE="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS_TYPE="linux"
    if [ -f /etc/alpine-release ]; then
        OS_TYPE="alpine"
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_TYPE="${ID}"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS_TYPE="macos"
fi

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 显示带颜色的消息
show_message() {
    local color="$1"
    local message="$2"
    if [ "$OS_TYPE" = "macos" ]; then
        echo "$message"
    else
        echo -e "${color}${message}${NC}"
    fi
}

# 检查是否以root运行（macOS允许非root）
check_root() {
    if [[ $EUID -ne 0 ]] && [[ "$OS_TYPE" != "macos" ]]; then
        show_message "$RED" "错误: 此脚本必须以root权限运行 (macOS除外)"
        exit 1
    fi
}

# 平台特定的命令别名
case "$OS_TYPE" in
    macos)
        # macOS 特定设置
        INSTALL_PATH="/usr/local/bin/xrayL"
        if [ ! -d "/usr/local/bin" ]; then
            mkdir -p /usr/local/bin
        fi
        if [ ! -d "/etc/xrayL" ]; then
            mkdir -p /etc/xrayL
        fi
        if [ ! -d "/var/log/xrayL" ]; then
            mkdir -p /var/log/xrayL
        fi
        # macOS 使用 launchd 而不是 systemd
        SERVICE_FILE="/Library/LaunchDaemons/com.xrayl.plist"
        ;;
    alpine)
        # Alpine Linux 特定设置
        INSTALL_PATH="/usr/local/bin/xrayL"
        SERVICE_FILE="/etc/init.d/xrayL"
        ;;
    *)
        # 标准 Linux 设置
        INSTALL_PATH="/usr/local/bin/xrayL"
        SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
        ;;
esac

# 生成UUID (跨平台兼容)
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    elif [[ -f /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    elif command -v python3 &> /dev/null; then
        python3 -c "import uuid; print(str(uuid.uuid4()))"
    elif command -v python &> /dev/null; then
        python -c "import uuid; print(str(uuid.uuid4()))"
    elif command -v node &> /dev/null; then
        node -e "console.log(require('crypto').randomUUID())"
    else
        # 使用随机字符串作为后备
        head -c 16 /dev/urandom | md5sum | cut -d' ' -f1 | sed 's/\(........\)\(....\)\(....\)\(....\)/\1-\2-\3-\4/'
    fi
}

# 生成随机密码 (跨平台兼容)
generate_random_password() {
    if command -v openssl &> /dev/null; then
        openssl rand -base64 12 | tr -d '\n=+/'
    elif command -v base64 &> /dev/null; then
        head -c 12 /dev/urandom | base64 | tr -d '\n=+/'
    else
        # 简单的随机字符串
        date +%s%N | md5sum | head -c 16
    fi
}

# 获取服务器IP地址 (跨平台兼容)
get_server_ip() {
    local ip_type=$1
    
    # 先尝试获取公网IP
    if [ "$ip_type" = "ipv4" ]; then
        # 尝试多个公网IP获取服务
        local public_ip=""
        for service in "ifconfig.me" "icanhazip.com" "ipinfo.io/ip" "api.ipify.org"; do
            if command -v curl &> /dev/null; then
                public_ip=$(curl -s -4 --connect-timeout 2 "$service" 2>/dev/null)
            elif command -v wget &> /dev/null; then
                public_ip=$(wget -q -O - --timeout=2 "http://$service" 2>/dev/null)
            fi
            [ -n "$public_ip" ] && break
        done
        
        if [ -n "$public_ip" ]; then
            echo "$public_ip"
            return
        fi
    elif [ "$ip_type" = "ipv6" ]; then
        # IPv6公网IP
        local public_ip=""
        for service in "ifconfig.me" "icanhazip.com"; do
            if command -v curl &> /dev/null; then
                public_ip=$(curl -s -6 --connect-timeout 2 "$service" 2>/dev/null)
            fi
            [ -n "$public_ip" ] && break
        done
        
        if [ -n "$public_ip" ]; then
            echo "$public_ip"
            return
        fi
    fi
    
    # 获取内网IP
    case "$OS_TYPE" in
        linux|alpine)
            if [ "$ip_type" = "ipv4" ]; then
                # Linux获取IPv4
                if command -v ip &> /dev/null; then
                    ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1
                elif command -v ifconfig &> /dev/null; then
                    ifconfig | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1
                fi
            elif [ "$ip_type" = "ipv6" ]; then
                # Linux获取IPv6
                if command -v ip &> /dev/null; then
                    ip -6 addr show | grep inet6 | grep -v '::1' | grep -v 'fe80' | awk '{print $2}' | cut -d'/' -f1 | head -1
                elif command -v ifconfig &> /dev/null; then
                    ifconfig | grep inet6 | grep -v '::1' | grep -v 'fe80' | awk '{print $2}' | cut -d'/' -f1 | head -1
                fi
            fi
            ;;
        macos)
            if [ "$ip_type" = "ipv4" ]; then
                # macOS获取IPv4
                ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1
            elif [ "$ip_type" = "ipv6" ]; then
                # macOS获取IPv6
                ifconfig | grep "inet6 " | grep -v '::1' | grep -v 'fe80' | awk '{print $2}' | head -1
            fi
            ;;
    esac
}

# 检查IPv6支持
check_ipv6_support() {
    case "$OS_TYPE" in
        linux|alpine)
            if [ -f /proc/sys/net/ipv6 ] || [ -d /proc/sys/net/ipv6 ]; then
                echo "enabled"
            else
                echo "disabled"
            fi
            ;;
        macos)
            if ifconfig | grep -q inet6; then
                echo "enabled"
            else
                echo "disabled"
            fi
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# 检查并安装依赖
install_dependencies() {
    show_message "$BLUE" "检查系统依赖..."
    
    case "$OS_TYPE" in
        ubuntu|debian)
            apt-get update
            apt-get install -y wget unzip curl
            ;;
        centos|rhel|fedora|rocky|alma)
            if command -v dnf &> /dev/null; then
                dnf install -y wget unzip curl
            elif command -v yum &> /dev/null; then
                yum install -y wget unzip curl
            fi
            ;;
        alpine)
            apk update
            apk add wget unzip curl
            ;;
        macos)
            if ! command -v brew &> /dev/null; then
                show_message "$YELLOW" "建议安装 Homebrew 以便管理依赖"
                read -p "是否安装 Homebrew? (y/N): " install_brew
                if [[ "$install_brew" =~ ^[Yy]$ ]]; then
                    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
                fi
            fi
            if command -v brew &> /dev/null; then
                brew install wget curl
            else
                show_message "$YELLOW" "请手动安装 wget 和 curl"
            fi
            ;;
        *)
            show_message "$YELLOW" "无法确定包管理器，请手动安装 wget, unzip, curl"
            ;;
    esac
}

# 安装 Xray
install_xray() {
    show_message "$BLUE" "正在安装 Xray..."
    
    # 检查是否已安装
    if [ -f "$INSTALL_PATH" ]; then
        show_message "$YELLOW" "Xray 已经安装，跳过安装步骤"
        return 0
    fi
    
    install_dependencies
    
    # 根据系统架构选择下载文件
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)
            ARCH_NAME="64"
            ;;
        aarch64|arm64)
            ARCH_NAME="arm64-v8a"
            ;;
        armv7l|armhf)
            ARCH_NAME="arm32-v7a"
            ;;
        i386|i686)
            ARCH_NAME="32"
            ;;
        *)
            show_message "$RED" "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    # 下载最新版本
    show_message "$BLUE" "获取 Xray 最新版本..."
    if command -v curl &> /dev/null; then
        LATEST_RELEASE=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    elif command -v wget &> /dev/null; then
        LATEST_RELEASE=$(wget -qO - https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    fi
    
    if [ -z "$LATEST_RELEASE" ]; then
        show_message "$YELLOW" "无法获取最新版本，使用默认版本 v1.8.3"
        XRAY_VERSION="v1.8.3"
    else
        XRAY_VERSION="v$LATEST_RELEASE"
        show_message "$GREEN" "找到最新版本: $XRAY_VERSION"
    fi
    
    # 下载 Xray
    XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-$ARCH_NAME.zip"
    show_message "$BLUE" "下载 Xray ($XRAY_VERSION) for $ARCH..."
    
    if ! wget -q --timeout=20 --tries=3 "$XRAY_URL" -O Xray-linux-${ARCH_NAME}.zip; then
        show_message "$RED" "下载失败，请检查网络连接"
        exit 1
    fi
    
    # 解压并安装
    unzip -q Xray-linux-${ARCH_NAME}.zip
    if [ ! -f "xray" ]; then
        show_message "$RED" "解压失败，xray 文件不存在"
        exit 1
    fi
    
    mv xray "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    rm -f Xray-linux-${ARCH_NAME}.zip
    
    # 创建服务文件
    create_service_file
    
    show_message "$GREEN" "Xray 安装完成!"
}

# 创建服务文件 (跨平台)
create_service_file() {
    case "$OS_TYPE" in
        macos)
            # macOS launchd plist 文件
            cat <<EOF > "$SERVICE_FILE"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.xrayl</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_PATH</string>
        <string>-c</string>
        <string>$CONFIG_FILE</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/xrayL/xrayL.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/xrayL/xrayL.log</string>
    <key>UserName</key>
    <string>nobody</string>
</dict>
</plist>
EOF
            # 加载服务
            launchctl load -w "$SERVICE_FILE" 2>/dev/null || true
            ;;
        alpine)
            # Alpine OpenRC init 脚本
            cat <<EOF > "$SERVICE_FILE"
#!/sbin/openrc-run

name="xrayL"
description="XrayL Proxy Service"
command="$INSTALL_PATH"
command_args="-c $CONFIG_FILE"
command_user="nobody:nobody"
pidfile="/run/\${RC_SVCNAME}.pid"
start_stop_daemon_args="--background --make-pidfile"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting \$name"
    start-stop-daemon --start --exec \$command \\
        --user \$command_user \\
        --pidfile \$pidfile \\
        --background --make-pidfile \\
        -- \$command_args
    eend \$?
}

stop() {
    ebegin "Stopping \$name"
    start-stop-daemon --stop --exec \$command \\
        --pidfile \$pidfile
    eend \$?
}
EOF
            chmod +x "$SERVICE_FILE"
            rc-update add xrayL default 2>/dev/null || true
            ;;
        *)
            # 标准 Linux systemd 服务
            cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=XrayL Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$INSTALL_PATH -c $CONFIG_FILE
Restart=on-failure
RestartSec=5
User=nobody
LimitNOFILE=4096
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable ${SERVICE_NAME}.service
            ;;
    esac
}

# 启动服务
start_service() {
    case "$OS_TYPE" in
        macos)
            launchctl load -w "$SERVICE_FILE" 2>/dev/null || true
            launchctl start com.xrayl 2>/dev/null || true
            ;;
        alpine)
            rc-service xrayL start 2>/dev/null || "$SERVICE_FILE" start
            ;;
        *)
            systemctl start ${SERVICE_NAME}.service 2>/dev/null || true
            ;;
    esac
}

# 停止服务
stop_service() {
    case "$OS_TYPE" in
        macos)
            launchctl stop com.xrayl 2>/dev/null || true
            ;;
        alpine)
            rc-service xrayL stop 2>/dev/null || "$SERVICE_FILE" stop
            ;;
        *)
            systemctl stop ${SERVICE_NAME}.service 2>/dev/null || true
            ;;
    esac
}

# 重启服务
restart_service() {
    stop_service
    sleep 2
    start_service
}

# 检查服务状态
check_service_status() {
    case "$OS_TYPE" in
        macos)
            launchctl list | grep -q com.xrayl && echo "running" || echo "stopped"
            ;;
        alpine)
            if rc-service xrayL status 2>/dev/null; then
                echo "running"
            else
                echo "stopped"
            fi
            ;;
        *)
            if systemctl is-active --quiet ${SERVICE_NAME}.service 2>/dev/null; then
                echo "running"
            else
                echo "stopped"
            fi
            ;;
    esac
}

# 卸载 Xray
uninstall_xray() {
    show_message "$RED" "准备卸载 Xray..."
    echo -e "${YELLOW}此操作将：${NC}"
    echo "1. 停止 Xray 服务"
    echo "2. 删除 Xray 程序"
    echo "3. 删除配置文件"
    echo "4. 删除服务文件"
    echo ""
    read -p "确定要卸载吗？(y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        show_message "$BLUE" "卸载已取消"
        return
    fi
    
    # 停止服务
    stop_service
    
    # 删除服务文件
    case "$OS_TYPE" in
        macos)
            launchctl unload -w "$SERVICE_FILE" 2>/dev/null || true
            rm -f "$SERVICE_FILE"
            ;;
        alpine)
            rc-update del xrayL 2>/dev/null || true
            rm -f "$SERVICE_FILE"
            ;;
        *)
            systemctl disable ${SERVICE_NAME}.service 2>/dev/null || true
            rm -f "$SERVICE_FILE"
            systemctl daemon-reload
            ;;
    esac
    
    # 删除文件
    rm -f "$INSTALL_PATH"
    rm -rf /etc/xrayL
    
    # 从.bashrc/.zshrc删除别名
    for rcfile in ~/.bashrc ~/.zshrc ~/.bash_profile ~/.profile; do
        if [ -f "$rcfile" ]; then
            sed -i.bak '/alias ss=/d' "$rcfile" 2>/dev/null || true
        fi
    done
    
    show_message "$GREEN" "Xray 卸载完成！"
    exit 0
}

# 设置快捷键
setup_alias() {
    local script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$SCRIPT_NAME"
    
    show_message "$BLUE" "设置快捷键 '$SS_ALIAS'..."
    
    # 确定shell配置文件
    local shell_rc=""
    if [ -n "$ZSH_VERSION" ]; then
        shell_rc="$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ]; then
        shell_rc="$HOME/.bashrc"
        if [[ "$OS_TYPE" == "macos" ]]; then
            shell_rc="$HOME/.bash_profile"
        fi
    fi
    
    if [ -n "$shell_rc" ]; then
        if ! grep -q "alias $SS_ALIAS=" "$shell_rc" 2>/dev/null; then
            echo "alias $SS_ALIAS='sudo $script_path 2>/dev/null || $script_path'" >> "$shell_rc"
            show_message "$GREEN" "已添加到 $shell_rc"
        else
            show_message "$YELLOW" "快捷键已存在于 $shell_rc"
        fi
    else
        show_message "$YELLOW" "无法确定shell类型，请手动添加别名到您的shell配置文件:"
        echo "alias $SS_ALIAS='sudo $script_path 2>/dev/null || $script_path'"
    fi
    
    show_message "$GREEN" "快捷键设置完成！"
    echo -e "${YELLOW}请运行以下命令使快捷键立即生效：${NC}"
    if [ -n "$ZSH_VERSION" ]; then
        echo "source ~/.zshrc"
    else
        echo "source ~/.bashrc"
    fi
    echo -e "${YELLOW}之后可以使用 'ss' 命令启动本脚本${NC}"
}

# Base64编码 (跨平台兼容)
base64_encode() {
    local data="$1"
    if command -v base64 &> /dev/null; then
        echo -n "$data" | base64 -w 0 2>/dev/null || echo -n "$data" | base64
    elif command -v python3 &> /dev/null; then
        echo -n "$data" | python3 -c "import sys, base64; print(base64.b64encode(sys.stdin.buffer.read()).decode())"
    elif command -v python &> /dev/null; then
        echo -n "$data" | python -c "import sys, base64; print base64.b64encode(sys.stdin.read())"
    else
        show_message "$RED" "错误: 需要 base64 编码但找不到合适的工具"
        echo "$data"
    fi
}

# 配置 Xray
config_xray() {
    config_type=$1
    
    if [ "$config_type" != "socks" ] && [ "$config_type" != "vmess" ]; then
        show_message "$RED" "类型错误！仅支持 socks 和 vmess."
        exit 1
    fi
    
    # 确保配置目录存在
    mkdir -p /etc/xrayL
    
    show_message "$BLUE" "配置 $config_type 代理..."
    
    # 检查IPv6支持
    IPV6_STATUS=$(check_ipv6_support)
    
    # 监听地址配置
    echo -e "\n${YELLOW}选择监听地址：${NC}"
    echo "1. 仅 IPv4 (0.0.0.0)"
    echo "2. 仅 IPv6 (::)"
    echo "3. IPv4 和 IPv6 (0.0.0.0 和 ::)"
    echo "4. 自定义监听地址"
    
    read -p "请选择 [1-4] (默认 1): " listen_choice
    listen_choice=${listen_choice:-1}
    
    case $listen_choice in
        1)
            LISTEN_ADDRESSES=("0.0.0.0")
            ;;
        2)
            LISTEN_ADDRESSES=("::")
            ;;
        3)
            LISTEN_ADDRESSES=("0.0.0.0" "::")
            ;;
        4)
            read -p "请输入自定义监听地址 (多个地址用空格分隔): " custom_addresses
            if [ -z "$custom_addresses" ]; then
                show_message "$RED" "错误: 必须输入监听地址"
                exit 1
            fi
            LISTEN_ADDRESSES=($custom_addresses)
            ;;
        *)
            LISTEN_ADDRESSES=("0.0.0.0")
            ;;
    esac
    
    # 端口配置
    read -p "起始端口 (默认 $DEFAULT_START_PORT): " START_PORT
    START_PORT=${START_PORT:-$DEFAULT_START_PORT}
    
    read -p "结束端口 (默认 $START_PORT 到 $DEFAULT_END_PORT): " END_PORT
    END_PORT=${END_PORT:-$DEFAULT_END_PORT}
    
    # 验证端口范围
    if [ $END_PORT -le $START_PORT ]; then
        show_message "$RED" "错误: 结束端口必须大于起始端口"
        exit 1
    fi
    
    PORT_COUNT=$((END_PORT - START_PORT + 1))
    show_message "$BLUE" "将创建 $PORT_COUNT 个端口 ($START_PORT-$END_PORT)"
    
    if [ "$config_type" == "socks" ]; then
        # SOCKS5 配置
        read -p "SOCKS 账号 (默认 $DEFAULT_SOCKS_USERNAME): " SOCKS_USERNAME
        SOCKS_USERNAME=${SOCKS_USERNAME:-$DEFAULT_SOCKS_USERNAME}
        
        read -p "SOCKS 密码 (默认随机生成): " SOCKS_PASSWORD
        if [ -z "$SOCKS_PASSWORD" ]; then
            SOCKS_PASSWORD=$(generate_random_password)
            show_message "$GREEN" "已生成随机密码: $SOCKS_PASSWORD"
        fi
        
    elif [ "$config_type" == "vmess" ]; then
        # VMESS 配置
        if [ -z "$DEFAULT_UUID" ]; then
            DEFAULT_UUID=$(generate_uuid)
        fi
        
        read -p "UUID (默认随机生成): " UUID
        if [ -z "$UUID" ]; then
            UUID="$DEFAULT_UUID"
            show_message "$GREEN" "已生成随机 UUID: $UUID"
        fi
        
        read -p "WebSocket 路径 (默认 $DEFAULT_WS_PATH): " WS_PATH
        WS_PATH=${WS_PATH:-$DEFAULT_WS_PATH}
    fi
    
    # 生成配置
    config_content=""
    
    # 添加日志配置
    config_content+="[log]\n"
    config_content+="loglevel = \"warning\"\n"
    config_content+="logDir = \"/var/log/xrayL/\"\n\n"
    
    # 为每个监听地址创建 inbound
    for listen_addr in "${LISTEN_ADDRESSES[@]}"; do
        config_content+="[[inbounds]]\n"
        config_content+="port = \"$START_PORT-$END_PORT\"\n"
        config_content+="listen = \"$listen_addr\"\n"
        config_content+="protocol = \"$config_type\"\n"
        config_content+="tag = \"${config_type}_inbound_${listen_addr//[.:]/_}\"\n"
        config_content+="[inbounds.settings]\n"
        
        if [ "$config_type" == "socks" ]; then
            config_content+="auth = \"password\"\n"
            config_content+="udp = true\n"
            config_content+="[[inbounds.settings.accounts]]\n"
            config_content+="user = \"$SOCKS_USERNAME\"\n"
            config_content+="pass = \"$SOCKS_PASSWORD\"\n"
            
        elif [ "$config_type" == "vmess" ]; then
            config_content+="[[inbounds.settings.clients]]\n"
            config_content+="id = \"$UUID\"\n"
            config_content+="alterId = 0\n"
            config_content+="[inbounds.streamSettings]\n"
            config_content+="network = \"ws\"\n"
            config_content+="[inbounds.streamSettings.wsSettings]\n"
            config_content+="path = \"$WS_PATH\"\n"
        fi
        config_content+="\n"
    done
    
    # 添加 outbound
    config_content+="[[outbounds]]\n"
    config_content+="protocol = \"freedom\"\n"
    config_content+="tag = \"direct_out\"\n\n"
    
    # 路由配置
    config_content+="[[routing.rules]]\n"
    config_content+="type = \"field\"\n"
    config_content+="inboundTag = ["
    for i in "${!LISTEN_ADDRESSES[@]}"; do
        if [ $i -gt 0 ]; then
            config_content+=", "
        fi
        config_content+="\"${config_type}_inbound_${LISTEN_ADDRESSES[$i]//[.:]/_}\""
    done
    config_content+="]\n"
    config_content+="outboundTag = \"direct_out\"\n"
    
    # 写入配置文件
    echo -e "$config_content" > $CONFIG_FILE
    
    # 确保日志目录存在
    mkdir -p /var/log/xrayL
    chown nobody:nogroup /var/log/xrayL 2>/dev/null || true
    
    # 重启服务
    restart_service
    sleep 2
    
    # 显示状态
    show_message "$GREEN" "\n================ 配置完成 ================"
    echo "服务状态: $(check_service_status)"
    
    echo ""
    show_message "$GREEN" "================ 配置信息 ================"
    echo "代理类型: $config_type"
    echo "端口范围: $START_PORT-$END_PORT ($PORT_COUNT 个端口)"
    echo "监听地址: ${LISTEN_ADDRESSES[*]}"
    
    # 生成订阅信息
    generate_subscription "$config_type" "$START_PORT" "$UUID" "$SOCKS_USERNAME" "$SOCKS_PASSWORD" "$WS_PATH" "${LISTEN_ADDRESSES[@]}"
}

# 生成订阅信息
generate_subscription() {
    local config_type=$1
    local start_port=$2
    local uuid=$3
    local username=$4
    local password=$5
    local ws_path=$6
    shift 6
    local listen_addresses=("$@")
    
    # 获取服务器IP
    local server_ipv4=$(get_server_ip "ipv4")
    local server_ipv6=$(get_server_ip "ipv6")
    
    # 清空订阅文件
    > $SUBSCRIPTION_FILE
    
    show_message "$CYAN" "\n================ 节点订阅信息 ================"
    
    if [ "$config_type" == "socks" ]; then
        echo "SOCKS5 节点配置:"
        
        # 为每个监听地址生成配置
        for listen_addr in "${listen_addresses[@]}"; do
            # 根据监听地址选择对应的服务器IP
            if [[ "$listen_addr" == "::" ]] || [[ "$listen_addr" == *:* ]]; then
                # IPv6 监听地址
                if [ -n "$server_ipv6" ]; then
                    SERVER_IP="$server_ipv6"
                else
                    SERVER_IP="$listen_addr"
                fi
            else
                # IPv4 监听地址
                if [ -n "$server_ipv4" ]; then
                    SERVER_IP="$server_ipv4"
                else
                    SERVER_IP="$listen_addr"
                fi
            fi
            
            echo "服务器: $SERVER_IP"
            echo "端口: $start_port-$((start_port + PORT_COUNT - 1))"
            echo "用户名: $username"
            echo "密码: $password"
            echo ""
            
            # 生成订阅链接
            for port in $(seq $start_port $((start_port + PORT_COUNT - 1))); do
                SOCKS_CONFIG="socks://$username:$password@$SERVER_IP:$port"
                ENCODED_CONFIG=$(base64_encode "$SOCKS_CONFIG")
                echo "$ENCODED_CONFIG" >> $SUBSCRIPTION_FILE
                echo "订阅链接 (端口 $port):"
                echo "socks://$username:$password@$SERVER_IP:$port"
                echo ""
            done
        done
        
    elif [ "$config_type" == "vmess" ]; then
        echo "VMESS 节点配置:"
        
        # 为每个监听地址生成配置
        for listen_addr in "${listen_addresses[@]}"; do
            # 根据监听地址选择对应的服务器IP
            if [[ "$listen_addr" == "::" ]] || [[ "$listen_addr" == *:* ]]; then
                # IPv6 监听地址
                if [ -n "$server_ipv6" ]; then
                    SERVER_IP="$server_ipv6"
                else
                    SERVER_IP="$listen_addr"
                fi
            else
                # IPv4 监听地址
                if [ -n "$server_ipv4" ]; then
                    SERVER_IP="$server_ipv4"
                else
                    SERVER_IP="$listen_addr"
                fi
            fi
            
            # 生成VMESS配置
            VMESS_JSON=$(cat <<EOF
{
  "v": "2",
  "ps": "XrayL-VMESS-${listen_addr//[.:]/_}",
  "add": "$SERVER_IP",
  "port": "$start_port",
  "id": "$uuid",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "",
  "path": "$ws_path",
  "tls": "none"
}
EOF
)
            
            # Base64编码VMESS配置
            ENCODED_JSON=$(base64_encode "$VMESS_JSON")
            SUBSCRIPTION_LINK="vmess://$ENCODED_JSON"
            
            echo "$SUBSCRIPTION_LINK" >> $SUBSCRIPTION_FILE
            
            echo "节点名称: XrayL-VMESS-${listen_addr//[.:]/_}"
            echo "服务器: $SERVER_IP"
            echo "端口: $start_port"
            echo "UUID: $uuid"
            echo "传输协议: WebSocket"
            echo "路径: $ws_path"
            echo ""
            echo "订阅链接:"
            echo "$SUBSCRIPTION_LINK"
            echo ""
        done
    fi
    
    # 生成聚合订阅链接
    generate_aggregate_subscription
    
    show_message "$CYAN" "============================================="
}

# 生成聚合订阅链接
generate_aggregate_subscription() {
    if [ -f "$SUBSCRIPTION_FILE" ] && [ -s "$SUBSCRIPTION_FILE" ]; then
        # 将所有配置合并并用换行符分隔
        AGGREGATE_CONFIG=$(cat "$SUBSCRIPTION_FILE" | tr '\n' '|' | sed 's/|$//')
        ENCODED_AGGREGATE=$(base64_encode "$AGGREGATE_CONFIG")
        
        echo -e "\n${GREEN}聚合订阅链接 (包含所有节点):${NC}"
        local server_ip=$(get_server_ip "ipv4")
        if [ -n "$server_ip" ]; then
            echo "http://$server_ip/xrayl-subscription.txt"
            # 保存订阅URL
            echo "http://$server_ip/xrayl-subscription.txt" > $SUBSCRIPTION_URL_FILE
        fi
        echo ""
        echo "Base64编码订阅:"
        echo "$ENCODED_AGGREGATE"
    fi
}

# 导出配置到文件
export_config() {
    local export_type=$1
    local file_path=$2
    
    if [ -z "$file_path" ]; then
        # 默认导出路径
        local timestamp=$(date +%Y%m%d_%H%M%S)
        file_path="/tmp/xrayl_${export_type}_${timestamp}.txt"
    fi
    
    case "$export_type" in
        config)
            if [ ! -f "$CONFIG_FILE" ]; then
                show_message "$RED" "配置文件不存在"
                return 1
            fi
            cp "$CONFIG_FILE" "$file_path"
            show_message "$GREEN" "配置已导出到: $file_path"
            ;;
        subscription)
            if [ ! -f "$SUBSCRIPTION_FILE" ] || [ ! -s "$SUBSCRIPTION_FILE" ]; then
                show_message "$YELLOW" "订阅文件不存在或为空"
                return 1
            fi
            cp "$SUBSCRIPTION_FILE" "$file_path"
            show_message "$GREEN" "订阅已导出到: $file_path"
            ;;
        all)
            local timestamp=$(date +%Y%m%d_%H%M%S)
            local export_dir="/tmp/xrayl_export_${timestamp}"
            mkdir -p "$export_dir"
            
            if [ -f "$CONFIG_FILE" ]; then
                cp "$CONFIG_FILE" "$export_dir/config.toml"
            fi
            if [ -f "$SUBSCRIPTION_FILE" ] && [ -s "$SUBSCRIPTION_FILE" ]; then
                cp "$SUBSCRIPTION_FILE" "$export_dir/subscription.txt"
            fi
            # 创建说明文件
            cat > "$export_dir/README.md" <<EOF
# XrayL 配置导出
导出时间: $(date)
操作系统: $OS_TYPE

包含文件:
1. config.toml - Xray 配置文件
2. subscription.txt - 节点订阅链接

使用说明:
1. 配置文件用于恢复服务配置
2. 订阅链接用于客户端导入节点
EOF
            tar -czf "$file_path.tar.gz" -C /tmp "xrayl_export_${timestamp}"
            rm -rf "$export_dir"
            show_message "$GREEN" "所有配置已导出到: $file_path.tar.gz"
            ;;
        *)
            show_message "$RED" "错误的导出类型，支持: config, subscription, all"
            return 1
            ;;
    esac
    
    # 显示文件内容预览
    if [[ "$export_type" != "all" ]]; then
        echo ""
        echo -e "${CYAN}文件内容预览 (前10行):${NC}"
        head -10 "$file_path" 2>/dev/null || true
    fi
    
    return 0
}

# 导入配置
import_config() {
    local import_file=$1
    
    if [ -z "$import_file" ] || [ ! -f "$import_file" ]; then
        show_message "$RED" "请指定有效的配置文件路径"
        return 1
    fi
    
    # 检测文件类型
    local file_type="unknown"
    if [[ "$import_file" == *.toml ]]; then
        file_type="config"
    elif [[ "$import_file" == *.txt ]]; then
        file_type="subscription"
    elif [[ "$import_file" == *.tar.gz ]] || [[ "$import_file" == *.tgz ]]; then
        file_type="all"
    else
        # 尝试猜测文件类型
        if grep -q "^\[\[inbounds\]\]" "$import_file" 2>/dev/null; then
            file_type="config"
        elif grep -q "^vmess://" "$import_file" 2>/dev/null || grep -q "^socks://" "$import_file" 2>/dev/null; then
            file_type="subscription"
        fi
    fi
    
    case "$file_type" in
        config)
            # 备份原配置
            local backup_file="$CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
            if [ -f "$CONFIG_FILE" ]; then
                cp "$CONFIG_FILE" "$backup_file"
                show_message "$YELLOW" "原配置已备份到: $backup_file"
            fi
            
            # 导入新配置
            cp "$import_file" "$CONFIG_FILE"
            show_message "$GREEN" "配置已导入，重启服务中..."
            restart_service
            sleep 2
            show_message "$GREEN" "配置导入完成，服务状态: $(check_service_status)"
            ;;
        subscription)
            # 导入订阅
            cp "$import_file" "$SUBSCRIPTION_FILE"
            show_message "$GREEN" "订阅信息已导入"
            view_subscription
            ;;
        all)
            # 解压并导入所有配置
            local temp_dir="/tmp/xrayl_import_$(date +%s)"
            mkdir -p "$temp_dir"
            tar -xzf "$import_file" -C "$temp_dir" 2>/dev/null || {
                show_message "$RED" "解压失败"
                rm -rf "$temp_dir"
                return 1
            }
            
            # 查找配置文件
            local config_found=0
            for file in "$temp_dir"/*.toml "$temp_dir"/*/config.toml; do
                if [ -f "$file" ]; then
                    import_config "$file"
                    config_found=1
                    break
                fi
            done
            
            # 查找订阅文件
            for file in "$temp_dir"/*.txt "$temp_dir"/*/subscription.txt; do
                if [ -f "$file" ]; then
                    cp "$file" "$SUBSCRIPTION_FILE" 2>/dev/null && {
                        show_message "$GREEN" "订阅信息已导入"
                        view_subscription
                    }
                    break
                fi
            done
            
            rm -rf "$temp_dir"
            
            if [ $config_found -eq 0 ]; then
                show_message "$YELLOW" "未找到有效的配置文件"
            fi
            ;;
        *)
            show_message "$RED" "无法识别文件类型，请检查文件格式"
            return 1
            ;;
    esac
    
    return 0
}

# 查看订阅信息
view_subscription() {
    if [ ! -f "$SUBSCRIPTION_FILE" ] || [ ! -s "$SUBSCRIPTION_FILE" ]; then
        show_message "$YELLOW" "暂无订阅信息，请先配置节点"
        return
    fi
    
    show_message "$PURPLE" "\n=============== 节点订阅信息 ==============="
    
    echo -e "${CYAN}单个节点链接:${NC}"
    local line_num=1
    cat "$SUBSCRIPTION_FILE" | while read line; do
        echo "[$line_num] $line"
        line_num=$((line_num + 1))
    done
    
    echo ""
    echo -e "${CYAN}聚合订阅链接:${NC}"
    if [ -f "$SUBSCRIPTION_URL_FILE" ]; then
        local url=$(cat "$SUBSCRIPTION_URL_FILE" 2>/dev/null || echo "")
        if [ -n "$url" ]; then
            echo "$url"
        else
            # 重新生成聚合链接
            generate_aggregate_subscription
        fi
    else
        # 重新生成聚合链接
        generate_aggregate_subscription
    fi
    
    echo ""
    echo -e "${YELLOW}使用说明:${NC}"
    echo "1. 复制单个节点链接到客户端使用"
    echo "2. 使用聚合订阅链接一键导入所有节点"
    echo "3. 确保防火墙已开放相应端口"
    echo ""
    echo -e "${YELLOW}支持的客户端:${NC}"
    echo "- Windows: v2rayN, Clash for Windows"
    echo "- macOS: ClashX, ShadowsocksX-NG"
    echo "- Linux: Qv2ray, Clash for Linux"
    echo "- Android: v2rayNG, Clash for Android"
    echo "- iOS: Shadowrocket, Stash"
    
    show_message "$PURPLE" "============================================="
    
    # 提供复制选项
    echo ""
    read -p "是否复制聚合订阅链接到剪贴板? (y/N): " copy_choice
    if [[ "$copy_choice" =~ ^[Yy]$ ]]; then
        if command -v pbcopy &> /dev/null; then
            # macOS
            if [ -f "$SUBSCRIPTION_FILE" ]; then
                head -1 "$SUBSCRIPTION_FILE" | pbcopy
                show_message "$GREEN" "已复制第一个节点链接到剪贴板"
            fi
        elif command -v xclip &> /dev/null; then
            # Linux with xclip
            if [ -f "$SUBSCRIPTION_FILE" ]; then
                head -1 "$SUBSCRIPTION_FILE" | xclip -selection clipboard
                show_message "$GREEN" "已复制第一个节点链接到剪贴板"
            fi
        elif command -v wl-copy &> /dev/null; then
            # Wayland
            if [ -f "$SUBSCRIPTION_FILE" ]; then
                head -1 "$SUBSCRIPTION_FILE" | wl-copy
                show_message "$GREEN" "已复制第一个节点链接到剪贴板"
            fi
        else
            show_message "$YELLOW" "无法自动复制，请手动复制上面的链接"
        fi
    fi
    
    # 提供导出选项
    echo ""
    read -p "是否导出订阅信息到文件? (y/N): " export_choice
    if [[ "$export_choice" =~ ^[Yy]$ ]]; then
        local timestamp=$(date +%Y%m%d_%H%M%S)
        local export_file="/tmp/xrayl_subscription_${timestamp}.txt"
        export_config "subscription" "$export_file"
    fi
}

# 显示服务状态
show_status() {
    show_message "$BLUE" "XrayL 服务状态:"
    echo "操作系统: $OS_TYPE"
    echo "服务状态: $(check_service_status)"
    
    # 显示进程信息
    if pgrep -x "xrayL" > /dev/null 2>/dev/null || pgrep -f "xrayL -c" > /dev/null 2>/dev/null; then
        echo "进程运行: 是"
        if command -v ps &> /dev/null; then
            ps aux | grep -E "xrayL|/usr/local/bin/xrayL" | grep -v grep | head -1
        fi
    else
        echo "进程运行: 否"
    fi
    
    echo ""
    show_message "$BLUE" "网络信息:"
    local ipv4=$(get_server_ip "ipv4")
    local ipv6=$(get_server_ip "ipv6")
    echo "IPv4 地址: ${ipv4:-无}"
    echo "IPv6 地址: ${ipv6:-无}"
    echo "IPv6 支持: $(check_ipv6_support)"
    
    if [ -f "$CONFIG_FILE" ]; then
        echo ""
        show_message "$BLUE" "配置文件信息:"
        echo "配置文件: $CONFIG_FILE"
        
        # 显示关键配置信息
        if command -v grep &> /dev/null; then
            echo -e "\n${CYAN}监听配置:${NC}"
            grep -E "^(port|listen|protocol|tag) = " "$CONFIG_FILE" 2>/dev/null | head -10 || true
        fi
    else
        show_message "$YELLOW" "配置文件不存在: $CONFIG_FILE"
    fi
    
    # 显示订阅信息摘要
    if [ -f "$SUBSCRIPTION_FILE" ] && [ -s "$SUBSCRIPTION_FILE" ]; then
        echo ""
        show_message "$GREEN" "订阅信息摘要:"
        local node_count=$(wc -l < "$SUBSCRIPTION_FILE" 2>/dev/null || echo "0")
        echo "节点数量: $node_count"
        echo "查看完整订阅: 选择菜单选项 8 或运行 'ss subscription'"
    fi
    
    # 防火墙状态检查 (Linux/Alpine)
    if [[ "$OS_TYPE" == "linux" ]] || [[ "$OS_TYPE" == "alpine" ]]; then
        echo ""
        show_message "$YELLOW" "防火墙状态:"
        if command -v ufw &> /dev/null; then
            ufw status | head -5
        elif command -v firewall-cmd &> /dev/null; then
            firewall-cmd --state 2>/dev/null && echo "firewalld 正在运行"
        elif command -v iptables &> /dev/null; then
            echo "iptables 可用"
        fi
    fi
}

# 防火墙配置 (Linux/Alpine)
configure_firewall() {
    if [[ "$OS_TYPE" != "linux" ]] && [[ "$OS_TYPE" != "alpine" ]]; then
        show_message "$YELLOW" "防火墙配置仅支持 Linux 和 Alpine"
        return
    fi
    
    show_message "$BLUE" "配置防火墙..."
    
    if [ ! -f "$CONFIG_FILE" ]; then
        show_message "$RED" "错误: 请先配置 Xray"
        return
    fi
    
    # 从配置文件中提取端口
    local ports=$(grep -E 'port = "' "$CONFIG_FILE" | sed 's/.*port = "\([^"]*\)".*/\1/' | head -1)
    if [ -z "$ports" ]; then
        show_message "$RED" "无法从配置文件中提取端口"
        return
    fi
    
    # 解析端口范围
    local start_port end_port
    if [[ "$ports" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        start_port=${BASH_REMATCH[1]}
        end_port=${BASH_REMATCH[2]}
    elif [[ "$ports" =~ ^[0-9]+$ ]]; then
        start_port=$ports
        end_port=$ports
    else
        show_message "$RED" "无法解析端口范围: $ports"
        return
    fi
    
    echo "检测到端口范围: $start_port-$end_port"
    
    # 选择防火墙工具
    if command -v ufw &> /dev/null; then
        show_message "$GREEN" "检测到 UFW，正在配置..."
        for port in $(seq $start_port $end_port); do
            ufw allow $port/tcp 2>/dev/null && echo "已允许 TCP 端口 $port"
            ufw allow $port/udp 2>/dev/null && echo "已允许 UDP 端口 $port"
        done
        ufw reload
        
    elif command -v firewall-cmd &> /dev/null; then
        show_message "$GREEN" "检测到 firewalld，正在配置..."
        for port in $(seq $start_port $end_port); do
            firewall-cmd --permanent --add-port=$port/tcp 2>/dev/null && echo "已允许 TCP 端口 $port"
            firewall-cmd --permanent --add-port=$port/udp 2>/dev/null && echo "已允许 UDP 端口 $port"
        done
        firewall-cmd --reload 2>/dev/null
        
    elif command -v iptables &> /dev/null; then
        show_message "$GREEN" "检测到 iptables，正在配置..."
        for port in $(seq $start_port $end_port); do
            iptables -A INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null && echo "已允许 TCP 端口 $port"
            iptables -A INPUT -p udp --dport $port -j ACCEPT 2>/dev/null && echo "已允许 UDP 端口 $port"
        done
        
        # 尝试保存规则
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    else
        show_message "$YELLOW" "未检测到支持的防火墙工具，请手动配置"
        echo "需要开放的端口: $start_port-$end_port (TCP和UDP)"
    fi
    
    show_message "$GREEN" "防火墙配置完成"
}

# 备份和恢复功能
backup_config() {
    local backup_dir="/etc/xrayL/backups"
    mkdir -p "$backup_dir"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$backup_dir/xrayl_backup_${timestamp}.tar.gz"
    
    # 备份配置文件和订阅文件
    tar -czf "$backup_file" -C /etc/xrayL config.toml subscription.txt subscription_url.txt 2>/dev/null
    
    if [ -f "$backup_file" ]; then
        show_message "$GREEN" "备份已创建: $backup_file"
        
        # 列出所有备份
        echo ""
        echo -e "${CYAN}可用的备份文件:${NC}"
        ls -lh "$backup_dir"/*.tar.gz 2>/dev/null | tail -5 || true
    else
        show_message "$RED" "备份创建失败"
    fi
}

restore_backup() {
    local backup_dir="/etc/xrayL/backups"
    
    if [ ! -d "$backup_dir" ]; then
        show_message "$YELLOW" "备份目录不存在"
        return
    fi
    
    # 列出所有备份文件
    local backups=($(ls -t "$backup_dir"/*.tar.gz 2>/dev/null))
    
    if [ ${#backups[@]} -eq 0 ]; then
        show_message "$YELLOW" "没有可用的备份文件"
        return
    fi
    
    echo ""
    echo -e "${CYAN}可用的备份文件:${NC}"
    for i in "${!backups[@]}"; do
        echo "[$((i+1))] $(basename ${backups[$i]})"
    done
    
    echo ""
    read -p "选择要恢复的备份编号 (1-${#backups[@]}): " backup_choice
    
    if ! [[ "$backup_choice" =~ ^[0-9]+$ ]] || [ "$backup_choice" -lt 1 ] || [ "$backup_choice" -gt ${#backups[@]} ]; then
        show_message "$RED" "无效的选择"
        return
    fi
    
    local selected_backup="${backups[$((backup_choice-1))]}"
    
    # 备份当前配置
    local current_backup="$backup_dir/current_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "$current_backup" -C /etc/xrayL config.toml subscription.txt subscription_url.txt 2>/dev/null
    
    # 恢复选定的备份
    tar -xzf "$selected_backup" -C /etc/xrayL
    
    show_message "$GREEN" "备份已恢复，重启服务中..."
    restart_service
    sleep 2
    show_message "$GREEN" "恢复完成，服务状态: $(check_service_status)"
    echo "原配置已备份到: $current_backup"
}

# 主菜单
show_menu() {
    echo ""
    show_message "$GREEN" "============= XrayL 管理脚本 ============="
    show_message "$CYAN" "操作系统: $OS_TYPE | 架构: $(uname -m)"
    echo "1. 安装 Xray (如未安装)"
    echo "2. 配置 SOCKS5 代理"
    echo "3. 配置 VMESS 代理"
    echo "4. 显示服务状态和节点订阅"
    echo "5. 重启服务"
    echo "6. 停止服务"
    echo "7. 设置快捷键 (ss)"
    echo "8. 查看节点订阅信息"
    echo "9. 配置防火墙 (Linux/Alpine)"
    echo "10. 备份配置"
    echo "11. 恢复配置"
    echo "12. 导出配置"
    echo "13. 导入配置"
    echo "14. 卸载 XrayL"
    echo "0. 退出"
    echo "==========================================="
    echo -n "请选择操作 [0-14]: "
}

# 主函数
main() {
    # 初始化默认UUID
    if [ -z "$DEFAULT_UUID" ]; then
        DEFAULT_UUID=$(generate_uuid)
    fi
    
    check_root
    
    # 显示欢迎信息
    echo ""
    show_message "$PURPLE" "XrayL 跨平台代理管理脚本"
    echo "支持: macOS, Linux (Ubuntu/Debian/CentOS/RHEL/Alpine)"
    echo "版本: 2.0 | 作者: 自动生成"
    
    # 解析命令行参数
    case "$1" in
        install)
            install_xray
            exit 0
            ;;
        socks|vmess)
            install_xray
            config_xray "$1"
            exit 0
            ;;
        status)
            show_status
            exit 0
            ;;
        restart)
            restart_service
            show_status
            exit 0
            ;;
        stop)
            stop_service
            show_message "$GREEN" "服务已停止"
            exit 0
            ;;
        start)
            start_service
            show_message "$GREEN" "服务已启动"
            exit 0
            ;;
        alias)
            setup_alias
            exit 0
            ;;
        subscription|sub)
            view_subscription
            exit 0
            ;;
        firewall|fw)
            configure_firewall
            exit 0
            ;;
        backup)
            backup_config
            exit 0
            ;;
        restore)
            restore_backup
            exit 0
            ;;
        export)
            export_config "${2:-config}" "$3"
            exit 0
            ;;
        import)
            import_config "$2"
            exit 0
            ;;
        uninstall)
            uninstall_xray
            exit 0
            ;;
        help|--help|-h)
            show_message "$GREEN" "使用方法:"
            echo "  $0 [命令]"
            echo ""
            echo "命令:"
            echo "  install      - 安装 Xray"
            echo "  socks        - 配置 SOCKS5 代理"
            echo "  vmess        - 配置 VMESS 代理"
            echo "  status       - 显示服务状态和节点订阅"
            echo "  start        - 启动服务"
            echo "  stop         - 停止服务"
            echo "  restart      - 重启服务"
            echo "  alias        - 设置快捷键 ss"
            echo "  subscription - 查看节点订阅信息"
            echo "  firewall     - 配置防火墙 (Linux/Alpine)"
            echo "  backup       - 备份配置"
            echo "  restore      - 恢复配置"
            echo "  export       - 导出配置 (config/subscription/all)"
            echo "  import       - 导入配置"
            echo "  uninstall    - 卸载 Xray"
            echo "  help         - 显示帮助"
            echo ""
            echo "示例:"
            echo "  $0 socks      # 配置 SOCKS5"
            echo "  $0 vmess      # 配置 VMESS"
            echo "  $0 status     # 查看状态和订阅"
            echo "  $0 sub        # 查看订阅信息"
            echo "  $0 firewall   # 配置防火墙"
            echo "  $0 export all # 导出所有配置"
            echo "  $0 import backup.tar.gz # 导入配置"
            exit 0
            ;;
    esac
    
    # 交互式菜单模式
    while true; do
        show_menu
        read choice
        
        case $choice in
            1)
                install_xray
                ;;
            2)
                install_xray
                config_xray "socks"
                ;;
            3)
                install_xray
                config_xray "vmess"
                ;;
            4)
                show_status
                ;;
            5)
                restart_service
                show_message "$GREEN" "服务已重启"
                ;;
            6)
                stop_service
                show_message "$GREEN" "服务已停止"
                ;;
            7)
                setup_alias
                ;;
            8)
                view_subscription
                ;;
            9)
                configure_firewall
                ;;
            10)
                backup_config
                ;;
            11)
                restore_backup
                ;;
            12)
                echo ""
                echo "选择导出类型:"
                echo "1. 配置文件"
                echo "2. 订阅信息"
                echo "3. 所有配置"
                read -p "请选择 [1-3]: " export_type_choice
                case $export_type_choice in
                    1) export_config "config" ;;
                    2) export_config "subscription" ;;
                    3) export_config "all" ;;
                    *) show_message "$RED" "无效选择" ;;
                esac
                ;;
            13)
                read -p "请输入配置文件的完整路径: " import_file
                import_config "$import_file"
                ;;
            14)
                uninstall_xray
                ;;
            0)
                show_message "$BLUE" "退出脚本"
                exit 0
                ;;
            *)
                show_message "$RED" "无效选择，请重新输入"
                ;;
        esac
        
        echo ""
        read -p "按回车键继续..."
    done
}

# 运行主函数
main "$@"
