#!/bin/bash

# 脚本名称: xrayL.sh
# 功能: Xray 代理服务器管理脚本
# 支持: SOCKS5 和 VMESS+WebSocket 协议

DEFAULT_START_PORT=20000                         #默认起始端口
DEFAULT_END_PORT=20005                           #默认结束端口（创建端口范围）
DEFAULT_SOCKS_USERNAME="userb"                   #默认socks账号
DEFAULT_SOCKS_PASSWORD="passwordb"               #默认socks密码
DEFAULT_WS_PATH="/ws"                            #默认ws路径
DEFAULT_UUID=$(cat /proc/sys/kernel/random/uuid) #默认随机UUID
CONFIG_FILE="/etc/xrayL/config.toml"             #配置文件路径
SERVICE_NAME="xrayL"                             #服务名称
INSTALL_PATH="/usr/local/bin/xrayL"              #安装路径
SCRIPT_NAME="xrayL.sh"                           #脚本名称
SS_ALIAS="ss"                                    #快捷键别名

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 显示带颜色的消息
show_message() {
    local color="$1"
    local message="$2"
    echo -e "${color}${message}${NC}"
}

# 检查是否以root运行
check_root() {
    if [[ $EUID -ne 0 ]]; then
        show_message "$RED" "错误: 此脚本必须以root权限运行"
        exit 1
    fi
}

# 检查并安装依赖
install_dependencies() {
    show_message "$BLUE" "检查系统依赖..."
    if command -v apt-get &>/dev/null; then
        apt-get update
        apt-get install -y wget unzip curl
    elif command -v yum &>/dev/null; then
        yum install -y wget unzip curl
    elif command -v dnf &>/dev/null; then
        dnf install -y wget unzip curl
    else
        show_message "$YELLOW" "警告: 无法确定包管理器，请手动安装 wget, unzip, curl"
    fi
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
    
    # 下载最新版本
    show_message "$BLUE" "获取 Xray 最新版本..."
    LATEST_RELEASE=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    
    if [ -z "$LATEST_RELEASE" ]; then
        show_message "$YELLOW" "无法获取最新版本，使用默认版本 v1.8.3"
        XRAY_VERSION="v1.8.3"
    else
        XRAY_VERSION="v$LATEST_RELEASE"
        show_message "$GREEN" "找到最新版本: $XRAY_VERSION"
    fi
    
    # 下载 Xray
    XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-64.zip"
    show_message "$BLUE" "下载 Xray ($XRAY_VERSION)..."
    
    if ! wget -q --timeout=10 --tries=3 "$XRAY_URL" -O Xray-linux-64.zip; then
        show_message "$RED" "下载失败，请检查网络连接"
        exit 1
    fi
    
    # 解压并安装
    unzip -q Xray-linux-64.zip
    if [ ! -f "xray" ]; then
        show_message "$RED" "解压失败，xray 文件不存在"
        exit 1
    fi
    
    mv xray "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    rm -f Xray-linux-64.zip
    
    # 创建 systemd 服务
    cat <<EOF >/etc/systemd/system/${SERVICE_NAME}.service
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

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}.service
    
    show_message "$GREEN" "Xray 安装完成!"
}

# 卸载 Xray
uninstall_xray() {
    show_message "$RED" "准备卸载 Xray..."
    echo -e "${YELLOW}此操作将：${NC}"
    echo "1. 停止 Xray 服务"
    echo "2. 删除 Xray 程序"
    echo "3. 删除配置文件"
    echo "4. 删除 systemd 服务"
    echo ""
    read -p "确定要卸载吗？(y/N): " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        show_message "$BLUE" "卸载已取消"
        return
    fi
    
    # 停止服务
    if systemctl is-active --quiet ${SERVICE_NAME}.service; then
        systemctl stop ${SERVICE_NAME}.service
    fi
    
    # 禁用服务
    if systemctl is-enabled --quiet ${SERVICE_NAME}.service 2>/dev/null; then
        systemctl disable ${SERVICE_NAME}.service
    fi
    
    # 删除文件
    rm -f "$INSTALL_PATH"
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    rm -rf /etc/xrayL
    systemctl daemon-reload
    
    # 从.bashrc/.zshrc删除别名
    if [ -f ~/.bashrc ]; then
        sed -i '/alias ss=/d' ~/.bashrc
    fi
    if [ -f ~/.zshrc ]; then
        sed -i '/alias ss=/d' ~/.zshrc
    fi
    
    show_message "$GREEN" "Xray 卸载完成！"
    exit 0
}

# 设置快捷键
setup_alias() {
    local script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$SCRIPT_NAME"
    
    show_message "$BLUE" "设置快捷键 '$SS_ALIAS'..."
    
    # 检查bashrc
    if [ -f ~/.bashrc ]; then
        if ! grep -q "alias $SS_ALIAS=" ~/.bashrc; then
            echo "alias $SS_ALIAS='sudo $script_path'" >> ~/.bashrc
            show_message "$GREEN" "已添加到 ~/.bashrc"
        else
            show_message "$YELLOW" "快捷键已存在于 ~/.bashrc"
        fi
    fi
    
    # 检查zshrc
    if [ -f ~/.zshrc ]; then
        if ! grep -q "alias $SS_ALIAS=" ~/.zshrc; then
            echo "alias $SS_ALIAS='sudo $script_path'" >> ~/.zshrc
            show_message "$GREEN" "已添加到 ~/.zshrc"
        else
            show_message "$YELLOW" "快捷键已存在于 ~/.zshrc"
        fi
    fi
    
    show_message "$GREEN" "快捷键设置完成！"
    echo -e "${YELLOW}请运行以下命令使快捷键立即生效：${NC}"
    echo "对于 bash: source ~/.bashrc"
    echo "对于 zsh:  source ~/.zshrc"
    echo -e "${YELLOW}之后可以使用 'ss' 命令启动本脚本${NC}"
}

# 生成随机密码
generate_random_password() {
    tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c 16
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
        read -p "UUID (默认随机生成): " UUID
        if [ -z "$UUID" ]; then
            UUID=$(cat /proc/sys/kernel/random/uuid)
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
    
    # 创建多个端口的 inbound
    config_content+="[[inbounds]]\n"
    config_content+="port = \"$START_PORT-$END_PORT\"\n"
    config_content+="listen = \"0.0.0.0\"\n"
    config_content+="protocol = \"$config_type\"\n"
    config_content+="tag = \"${config_type}_inbound\"\n"
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
    
    # 添加 outbound
    config_content+="\n[[outbounds]]\n"
    config_content+="protocol = \"freedom\"\n"
    config_content+="tag = \"direct_out\"\n\n"
    
    # 路由配置
    config_content+="[[routing.rules]]\n"
    config_content+="type = \"field\"\n"
    config_content+="inboundTag = [\"${config_type}_inbound\"]\n"
    config_content+="outboundTag = \"direct_out\"\n"
    
    # 写入配置文件
    echo -e "$config_content" > $CONFIG_FILE
    
    # 确保日志目录存在
    mkdir -p /var/log/xrayL
    chown nobody:nogroup /var/log/xrayL 2>/dev/null || true
    
    # 重启服务
    systemctl restart ${SERVICE_NAME}.service
    sleep 2
    
    # 显示状态
    show_message "$GREEN" "\n================ 配置完成 ================"
    systemctl --no-pager status ${SERVICE_NAME}.service
    
    echo ""
    show_message "$GREEN" "================ 配置信息 ================"
    echo "代理类型: $config_type"
    echo "端口范围: $START_PORT-$END_PORT ($PORT_COUNT 个端口)"
    echo "监听地址: 0.0.0.0 (所有网络接口)"
    
    if [ "$config_type" == "socks" ]; then
        echo "SOCKS 账号: $SOCKS_USERNAME"
        echo "SOCKS 密码: $SOCKS_PASSWORD"
        echo ""
        echo "SOCKS5 连接示例:"
        echo "服务器: $(curl -s ifconfig.me || hostname -I | awk '{print $1}')"
        echo "端口: $START_PORT-$END_PORT (任选其一)"
        echo "用户名: $SOCKS_USERNAME"
        echo "密码: $SOCKS_PASSWORD"
        
    elif [ "$config_type" == "vmess" ]; then
        echo "UUID: $UUID"
        echo "WebSocket 路径: $WS_PATH"
        echo "传输协议: WebSocket"
        echo ""
        echo "VMESS 配置 (可用于 v2rayN、Clash 等):"
        SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
        cat <<EOF
{
  "v": "2",
  "ps": "XrayL-VMESS",
  "add": "$SERVER_IP",
  "port": "$START_PORT",
  "id": "$UUID",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "",
  "path": "$WS_PATH",
  "tls": "none"
}
EOF
    fi
    
    echo -e "\n${GREEN}配置文件位置: $CONFIG_FILE${NC}"
    show_message "$YELLOW" "服务已设置为开机自启"
}

# 显示服务状态
show_status() {
    show_message "$BLUE" "XrayL 服务状态:"
    systemctl --no-pager status ${SERVICE_NAME}.service
    
    if [ -f "$CONFIG_FILE" ]; then
        echo ""
        show_message "$BLUE" "配置文件内容:"
        cat "$CONFIG_FILE"
    else
        show_message "$YELLOW" "配置文件不存在: $CONFIG_FILE"
    fi
}

# 主菜单
show_menu() {
    echo ""
    show_message "$GREEN" "============= XrayL 管理脚本 ============="
    echo "1. 安装 Xray (如未安装)"
    echo "2. 配置 SOCKS5 代理"
    echo "3. 配置 VMESS 代理"
    echo "4. 显示服务状态"
    echo "5. 重启服务"
    echo "6. 停止服务"
    echo "7. 设置快捷键 (ss)"
    echo "8. 卸载 XrayL"
    echo "0. 退出"
    echo "==========================================="
    echo -n "请选择操作 [0-8]: "
}

# 主函数
main() {
    check_root
    
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
            systemctl restart ${SERVICE_NAME}.service
            show_status
            exit 0
            ;;
        stop)
            systemctl stop ${SERVICE_NAME}.service
            show_message "$GREEN" "服务已停止"
            exit 0
            ;;
        alias)
            setup_alias
            exit 0
            ;;
        uninstall)
            uninstall_xray
            exit 0
            ;;
        help)
            show_message "$GREEN" "使用方法:"
            echo "  $0 [命令]"
            echo ""
            echo "命令:"
            echo "  install     - 安装 Xray"
            echo "  socks       - 配置 SOCKS5 代理"
            echo "  vmess       - 配置 VMESS 代理"
            echo "  status      - 显示服务状态"
            echo "  restart     - 重启服务"
            echo "  stop        - 停止服务"
            echo "  alias       - 设置快捷键 ss"
            echo "  uninstall   - 卸载 Xray"
            echo "  help        - 显示帮助"
            echo ""
            echo "示例:"
            echo "  $0 socks      # 配置 SOCKS5"
            echo "  $0 vmess      # 配置 VMESS"
            echo "  $0 status     # 查看状态"
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
                systemctl restart ${SERVICE_NAME}.service
                show_message "$GREEN" "服务已重启"
                ;;
            6)
                systemctl stop ${SERVICE_NAME}.service
                show_message "$GREEN" "服务已停止"
                ;;
            7)
                setup_alias
                ;;
            8)
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
