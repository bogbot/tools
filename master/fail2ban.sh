#!/bin/bash

# Fail2ban 自动安装脚本
# 适用于使用 systemd journal 的 Debian/Ubuntu 系统

set -e  # 遇到错误时退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印函数
print_step() {
    echo -e "${BLUE}[步骤] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[成功] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[警告] $1${NC}"
}

print_error() {
    echo -e "${RED}[错误] $1${NC}"
}

print_info() {
    echo -e "${YELLOW}[信息] $1${NC}"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本需要root权限运行"
        echo "请使用: sudo $0"
        exit 1
    fi
}

# 小时转换为秒
hours_to_seconds() {
    local hours=$1
    echo $((hours * 3600))
}

# 获取用户输入
get_user_input() {
    print_step "收集配置信息"
    
    # 获取要忽略的IP地址
    echo -n "请输入要忽略的IP地址（多个IP用空格分隔，回车跳过）: "
    read -r IGNORE_IPS
    
    # 获取SSH端口
    echo -n "请输入SSH端口（默认22，回车使用默认值）: "
    read -r SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    
    # 获取标准保护配置
    echo ""
    print_info "=== 配置SSH标准保护规则 ==="
    echo -n "标准保护几次失败后封禁？（默认3次，回车使用默认值）: "
    read -r STANDARD_MAXRETRY
    STANDARD_MAXRETRY=${STANDARD_MAXRETRY:-3}
    
    echo -n "标准保护封禁多少小时？（默认960小时，回车使用默认值）: "
    read -r STANDARD_BANTIME_HOURS
    STANDARD_BANTIME_HOURS=${STANDARD_BANTIME_HOURS:-960}
    STANDARD_BANTIME_SECONDS=$(hours_to_seconds $STANDARD_BANTIME_HOURS)
    
    # 获取激进保护配置
    echo ""
    print_info "=== 配置SSH激进保护规则 ==="
    echo -n "激进保护几次失败后封禁？（默认2次，回车使用默认值）: "
    read -r AGGRESSIVE_MAXRETRY
    AGGRESSIVE_MAXRETRY=${AGGRESSIVE_MAXRETRY:-2}
    
    echo -n "激进保护封禁多少小时？（默认960小时，回车使用默认值）: "
    read -r AGGRESSIVE_BANTIME_HOURS
    AGGRESSIVE_BANTIME_HOURS=${AGGRESSIVE_BANTIME_HOURS:-960}
    AGGRESSIVE_BANTIME_SECONDS=$(hours_to_seconds $AGGRESSIVE_BANTIME_HOURS)
    
    # 确认配置
    echo ""
    print_info "=== 配置确认 ==="
    print_info "忽略的IP地址: ${IGNORE_IPS:-无}"
    print_info "SSH端口: $SSH_PORT"
    print_info "标准保护: ${STANDARD_MAXRETRY}次失败封禁${STANDARD_BANTIME_HOURS}小时"
    print_info "激进保护: ${AGGRESSIVE_MAXRETRY}次探测封禁${AGGRESSIVE_BANTIME_HOURS}小时"
    echo ""
    
    echo -n "确认安装？(y/N): "
    read -r CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        print_info "安装已取消"
        exit 0
    fi
}

# 安装必要软件包
install_packages() {
    print_step "更新软件包列表并安装 fail2ban"
    
    apt update
    print_success "软件包列表更新完成"
    
    # 安装时会出现 iptables-persistent 的对话框，自动选择 Yes
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    
    apt install -y fail2ban iptables-persistent
    print_success "fail2ban 和 iptables-persistent 安装完成"
}

# 创建自定义过滤器
create_filter() {
    print_step "创建自定义SSH过滤器"
    
    cat > /etc/fail2ban/filter.d/sshd-systemd.conf << 'EOF'
[Definition]
# 针对systemd journal的SSH攻击过滤器
failregex = ^.*sshd\[\d+\]:\s+Failed password for .* from <HOST> port \d+ ssh2?$
            ^.*sshd\[\d+\]:\s+Invalid user .* from <HOST> port \d+.*$
            ^.*sshd\[\d+\]:\s+Disconnected from authenticating user .* <HOST> port \d+ \[preauth\]$
            ^.*sshd\[\d+\]:\s+Received disconnect from <HOST> port \d+:11: Bye Bye \[preauth\]$
            ^.*sshd\[\d+\]:\s+Connection closed by <HOST> port \d+ \[preauth\]$
            ^.*sshd\[\d+\]:\s+Disconnected from invalid user .* <HOST> port \d+ \[preauth\]$

# 忽略成功登录
ignoreregex = ^.*sshd\[\d+\]:\s+Accepted .* from <HOST> port \d+ .*$

[INCLUDES]
before = common.conf
EOF
    
    print_success "自定义过滤器创建完成: /etc/fail2ban/filter.d/sshd-systemd.conf"
}

# 创建jail配置
create_jail_config() {
    print_step "创建 fail2ban 主配置文件"
    
    # 构建忽略IP列表
    IGNORE_IP_LIST="127.0.0.1/8 ::1"
    if [[ -n "$IGNORE_IPS" ]]; then
        IGNORE_IP_LIST="$IGNORE_IP_LIST $IGNORE_IPS"
    fi
    
    # 设置端口配置
    if [[ "$SSH_PORT" == "22" ]]; then
        PORT_CONFIG="ssh"
    else
        PORT_CONFIG="$SSH_PORT"
    fi
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 315360000
findtime = 600
maxretry = 5
banaction = iptables-multiport
action = %(action_)s
ignoreip = $IGNORE_IP_LIST

[sshd]
enabled = true
filter = sshd
port = $PORT_CONFIG
maxretry = $STANDARD_MAXRETRY
findtime = 600
bantime = $STANDARD_BANTIME_SECONDS
backend = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd
action = iptables-multiport[name=SSH, port="%(port)s", protocol=tcp]

[sshd-aggressive]
enabled = true
filter = sshd-systemd
port = $PORT_CONFIG
maxretry = $AGGRESSIVE_MAXRETRY
findtime = 300
bantime = $AGGRESSIVE_BANTIME_SECONDS
backend = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd
action = iptables-multiport[name=SSH-AGG, port="%(port)s", protocol=tcp]
EOF
    
    print_success "主配置文件创建完成: /etc/fail2ban/jail.local"
    print_info "忽略的IP: $IGNORE_IP_LIST"
    print_info "SSH端口: $PORT_CONFIG"
    print_info "标准保护: ${STANDARD_MAXRETRY}次失败封禁${STANDARD_BANTIME_HOURS}小时"
    print_info "激进保护: ${AGGRESSIVE_MAXRETRY}次失败封禁${AGGRESSIVE_BANTIME_HOURS}小时"
}

# 验证SSH服务
verify_ssh_service() {
    print_step "验证SSH服务状态"
    
    if systemctl is-active --quiet ssh.service; then
        print_success "SSH服务正在运行"
        
        # 检查systemd journal访问（添加--no-pager避免分页）
        if journalctl _SYSTEMD_UNIT=ssh.service -n 1 --quiet --no-pager >/dev/null 2>&1; then
            print_success "systemd journal访问正常"
        else
            print_warning "无法访问SSH的systemd journal，可能影响日志检测"
        fi
    else
        print_error "SSH服务未运行，请检查SSH配置"
        exit 1
    fi
}

# 测试配置
test_configuration() {
    print_step "测试 fail2ban 配置"
    
    if fail2ban-client -t; then
        print_success "配置测试通过"
    else
        print_error "配置测试失败，请检查配置文件"
        exit 1
    fi
}

# 启动服务
start_service() {
    print_step "启动 fail2ban 服务"
    
    systemctl enable fail2ban
    print_success "fail2ban 已设置为开机自启"
    
    systemctl restart fail2ban
    print_success "fail2ban 服务已启动"
    
    # 等待服务完全启动
    sleep 2
    
    if systemctl is-active --quiet fail2ban; then
        print_success "fail2ban 服务运行正常"
    else
        print_error "fail2ban 服务启动失败"
        systemctl status fail2ban
        exit 1
    fi
}

# 验证安装
verify_installation() {
    print_step "验证安装结果"
    
    # 检查jail状态
    echo ""
    print_info "=== Fail2ban 状态 ==="
    fail2ban-client status
    
    echo ""
    print_info "=== SSH标准保护状态 ==="
    fail2ban-client status sshd
    
    echo ""
    print_info "=== SSH激进保护状态 ==="
    fail2ban-client status sshd-aggressive
    
    echo ""
    print_success "验证完成"
}

# 创建监控脚本
create_monitoring_script() {
    print_step "创建监控脚本"
    
    cat > /usr/local/bin/fail2ban-status.sh << 'EOF'
#!/bin/bash

# Fail2ban 状态监控脚本

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# 时间转换函数
seconds_to_readable() {
    local seconds=$1
    if [ "$seconds" = "-1" ]; then
        echo "永久封禁"
    else
        local days=$((seconds / 86400))
        local hours=$(((seconds % 86400) / 3600))
        local mins=$(((seconds % 3600) / 60))
        echo "${days}天${hours}小时${mins}分钟"
    fi
}

# 获取剩余封禁时间
get_remaining_time() {
    local jail=$1
    local ip=$2
    local ban_time=$(fail2ban-client get $jail bantime 2>/dev/null)
    
    if [ "$ban_time" = "-1" ]; then
        echo "永久"
        return
    fi
    
    # 获取封禁开始时间（从fail2ban日志中解析）
    local ban_start=$(grep "Ban $ip" /var/log/fail2ban.log | tail -1 | cut -d' ' -f1-2)
    if [ -z "$ban_start" ]; then
        echo "未知"
        return
    fi
    
    # 转换为时间戳
    local ban_timestamp=$(date -d "$ban_start" +%s 2>/dev/null)
    local current_timestamp=$(date +%s)
    local elapsed=$((current_timestamp - ban_timestamp))
    local remaining=$((ban_time - elapsed))
    
    if [ $remaining -le 0 ]; then
        echo "即将解封"
    else
        seconds_to_readable $remaining
    fi
}

# 显示详细的jail状态
show_jail_status() {
    local jail=$1
    local name=$2
    
    echo -e "${YELLOW}$name：${NC}"
    
    # 获取基本状态
    local status=$(fail2ban-client status $jail 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "  ${RED}jail '$jail' 未运行${NC}"
        return
    fi
    
    echo "$status"
    
    # 显示封禁策略
    local bantime=$(fail2ban-client get $jail bantime 2>/dev/null)
    local findtime=$(fail2ban-client get $jail findtime 2>/dev/null)
    local maxretry=$(fail2ban-client get $jail maxretry 2>/dev/null)
    
    echo -e "${BLUE}  封禁策略: ${maxretry}次失败(${findtime}秒内) → 封禁$(seconds_to_readable $bantime)${NC}"
    
    # 显示被封禁IP的详细信息
    local banned_ips=$(fail2ban-client get $jail banip 2>/dev/null)
    if [ -n "$banned_ips" ] && [ "$banned_ips" != "" ]; then
        echo -e "${RED}  被封禁的IP及剩余时间：${NC}"
        for ip in $banned_ips; do
            local remaining=$(get_remaining_time $jail $ip)
            echo "    $ip → 剩余: $remaining"
        done
    else
        echo "  当前无IP被封禁"
    fi
    echo
}

echo -e "${BLUE}========== Fail2ban 状态报告 $(date) ==========${NC}"
echo

echo -e "${YELLOW}1. 服务状态：${NC}"
if systemctl is-active --quiet fail2ban; then
    echo -e "${GREEN}运行中${NC}"
else
    echo -e "${RED}未运行${NC}"
fi
echo

echo -e "${YELLOW}2. 活跃的 jail：${NC}"
fail2ban-client status
echo

# 显示详细的jail状态
show_jail_status "sshd" "3. SSH 标准保护状态"
show_jail_status "sshd-aggressive" "4. SSH 激进保护状态"

echo -e "${YELLOW}5. 今日攻击统计：${NC}"
count=$(journalctl _SYSTEMD_UNIT=ssh.service --since today | grep -E "(Failed password|Invalid user)" | wc -l)
echo "攻击次数：$count"

if [ $count -gt 0 ]; then
    echo "攻击IP排行："
    journalctl _SYSTEMD_UNIT=ssh.service --since today | grep -E "(Failed password|Invalid user)" | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -nr | head -5
fi

echo
echo -e "${GREEN}========== 报告结束 ==========${NC}"
EOF
    
    chmod +x /usr/local/bin/fail2ban-status.sh
    print_success "监控脚本创建完成: /usr/local/bin/fail2ban-status.sh"
}

# 显示使用说明
show_usage_info() {
    print_step "显示使用说明"
    
    echo ""
    print_info "=== 安装完成！使用说明 ==="
    echo ""
    echo "📊 查看状态:"
    echo "   sudo /usr/local/bin/fail2ban-status.sh"
    echo ""
    echo "🔍 实时监控:"
    echo "   sudo tail -f /var/log/fail2ban.log"
    echo "   sudo journalctl -f _SYSTEMD_UNIT=ssh.service | grep -E '(Failed|Invalid|Connection closed)'"
    echo ""
    echo "⚙️  管理命令:"
    echo "   sudo fail2ban-client status                    # 查看总体状态"
    echo "   sudo fail2ban-client status sshd               # 查看SSH标准保护"
    echo "   sudo fail2ban-client status sshd-aggressive    # 查看SSH激进保护"
    echo "   sudo fail2ban-client set sshd bantime 秒数      # 快速修改封禁时间（运行时修改）"
    echo "   sudo fail2ban-client set sshd-aggressive bantime 秒数      # 快速修改封禁时间(激进)"
    echo "   sudo fail2ban-client get sshd bantime	    # 查看当前封禁时间设置"
    echo "   sudo fail2ban-client get sshd-aggressive bantime	    # 查看当前封禁时间设置(激进)"
    echo "   sudo fail2ban-client set sshd banip IP地址      # 手动封禁IP"
    echo "   sudo fail2ban-client set sshd unbanip IP地址    # 手动解封IP"
    echo ""
    echo "📋 当前保护规则:"
    echo "   • SSH标准保护: ${STANDARD_MAXRETRY}次密码失败 → 封禁${STANDARD_BANTIME_HOURS}小时"
    echo "   • SSH激进保护: ${AGGRESSIVE_MAXRETRY}次探测行为 → 封禁${AGGRESSIVE_BANTIME_HOURS}小时"
    echo "   • 忽略IP: $IGNORE_IP_LIST"
    echo ""
    print_success "Fail2ban 安装并配置完成！"
}

# 主函数
main() {
    echo -e "${BLUE}"
    echo "=================================="
    echo "    Fail2ban 自动安装脚本"
    echo "=================================="
    echo -e "${NC}"
    
    check_root
    get_user_input
    install_packages
    create_filter
    create_jail_config
    verify_ssh_service
    test_configuration
    start_service
    verify_installation
    create_monitoring_script
    show_usage_info
    
    echo ""
    print_success "🎉 所有步骤完成！你的服务器现在受到 Fail2ban 保护。"
}

# 运行主函数
main "$@"