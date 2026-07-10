#!/usr/bin/env bash

set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
cyan='\033[0;36m'
plain='\033[0m'

REPO_OWNER="${REPO_OWNER:-AnixOps}"
REPO_NAME="${REPO_NAME:-V2bX_AnixOps}"
INSTALL_SCRIPT_REF="${INSTALL_SCRIPT_REF:-${REPO_BRANCH:-dev_new}}"

SERVICE_NAME="V2bX"
INSTALL_DIR="/usr/local/V2bX"
BIN_PATH="${INSTALL_DIR}/V2bX"
CONFIG_DIR="/etc/V2bX"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}"
CMD_NAME="v2bx-anixops"

info() {
    echo -e "${green}$*${plain}"
}

warn() {
    echo -e "${yellow}$*${plain}"
}

error() {
    echo -e "${red}$*${plain}"
}

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "错误：请使用 root 用户运行 V2bX 管理脚本"
        exit 1
    fi
}

is_alpine() {
    [[ -f /etc/alpine-release ]]
}

is_installed() {
    [[ -x "${BIN_PATH}" ]]
}

run_state() {
    if ! is_installed; then
        echo "not_installed"
        return
    fi

    if is_alpine; then
        local status_text
        status_text="$(rc-service "${SERVICE_NAME}" status 2>/dev/null || true)"
        if echo "${status_text}" | grep -qi "started"; then
            echo "running"
        else
            echo "stopped"
        fi
        return
    fi

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo "running"
    else
        echo "stopped"
    fi
}

enable_state() {
    if ! is_installed; then
        echo "not_installed"
        return
    fi

    if is_alpine; then
        if rc-update show 2>/dev/null | grep -Eq "^${SERVICE_NAME}[[:space:]]"; then
            echo "enabled"
        else
            echo "disabled"
        fi
        return
    fi

    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo "enabled"
    else
        echo "disabled"
    fi
}

state_label() {
    case "$1" in
        running) echo -e "${green}运行中${plain}" ;;
        stopped) echo -e "${yellow}未运行${plain}" ;;
        enabled) echo -e "${green}已启用${plain}" ;;
        disabled) echo -e "${yellow}未启用${plain}" ;;
        not_installed) echo -e "${red}未安装${plain}" ;;
        *) echo -e "${yellow}未知${plain}" ;;
    esac
}

install_state_label() {
    if [[ "$1" == "not_installed" ]]; then
        echo -e "${red}未安装${plain}"
    else
        echo -e "${green}已安装${plain}"
    fi
}

svc_start() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" start
    else
        systemctl start "${SERVICE_NAME}"
    fi
}

svc_stop() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" stop
    else
        systemctl stop "${SERVICE_NAME}"
    fi
}

svc_restart() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" restart
    else
        systemctl restart "${SERVICE_NAME}"
    fi
}

svc_status() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" status
    else
        systemctl --no-pager --full status "${SERVICE_NAME}"
    fi
}

svc_enable() {
    if is_alpine; then
        rc-update add "${SERVICE_NAME}" default >/dev/null 2>&1 || true
    else
        systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
}

svc_disable() {
    if is_alpine; then
        rc-update del "${SERVICE_NAME}" default >/dev/null 2>&1 || true
    else
        systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
}

show_log() {
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u "${SERVICE_NAME}" -n 200 --no-pager -e
        return
    fi

    if command -v logread >/dev/null 2>&1; then
        logread | grep -i "${SERVICE_NAME}" | tail -n 200
        return
    fi

    warn "当前系统无法自动读取日志，请手动查看系统日志"
}

run_install_script() {
    local version="${1:-}"
    local script_ref="${INSTALL_SCRIPT_REF}"
    local tmp_file
    local rc=0

    if [[ -n "${version}" ]]; then
        script_ref="${version}"
    fi
    tmp_file="$(mktemp)"

    curl -fsSL "${RAW_BASE}/${script_ref}/scripts/install.sh" -o "${tmp_file}"
    chmod +x "${tmp_file}"
    if [[ -n "${version}" ]]; then
        "${tmp_file}" "${version}" || rc=$?
    else
        "${tmp_file}" || rc=$?
    fi

    rm -f "${tmp_file}"
    return "${rc}"
}

run_bin_subcommand() {
    local sub_cmd="$1"
    shift || true

    if ! is_installed; then
        error "未检测到可执行文件：${BIN_PATH}"
        return 1
    fi

    "${BIN_PATH}" "${sub_cmd}" "$@"
}

edit_config() {
    local cfg="${CONFIG_DIR}/config.json"
    local editor="${EDITOR:-}"

    if [[ ! -f "${cfg}" ]]; then
        error "配置文件不存在：${cfg}"
        return 1
    fi

    if [[ -z "${editor}" ]]; then
        for e in nano vim vi; do
            if command -v "${e}" >/dev/null 2>&1; then
                editor="${e}"
                break
            fi
        done
    fi

    if [[ -z "${editor}" ]]; then
        error "未找到可用编辑器（nano/vim/vi）"
        return 1
    fi

    "${editor}" "${cfg}"
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}

prompt_text() {
    local prompt="$1"
    local default="${2:-}"
    local value=""
    if [[ -n "${default}" ]]; then
        read -r -p "${prompt} [默认: ${default}]: " value
        value="${value:-${default}}"
    else
        read -r -p "${prompt}: " value
    fi
    printf '%s' "${value}"
}

prompt_required_text() {
    local prompt="$1"
    local value=""
    while true; do
        read -r -p "${prompt}: " value
        if [[ -n "${value}" ]]; then
            printf '%s' "${value}"
            return
        fi
        warn "该项不能为空，请重新输入"
    done
}

prompt_int() {
    local prompt="$1"
    local default="${2:-}"
    local value=""
    while true; do
        if [[ -n "${default}" ]]; then
            read -r -p "${prompt} [默认: ${default}]: " value
            value="${value:-${default}}"
        else
            read -r -p "${prompt}: " value
        fi

        if [[ "${value}" =~ ^[0-9]+$ ]]; then
            printf '%s' "${value}"
            return
        fi
        warn "请输入有效的整数"
    done
}

init_config_wizard() {
    local cfg="${CONFIG_DIR}/config.json"
    local backup=""
    local core_type api_host api_key node_id node_type timeout listen_ip send_ip cert_mode
    local transport grpc_host grpc_use_tls grpc_server_name grpc_keepalive
    local core_json

    info "进入初始化配置向导（将写入 ${cfg}）"
    mkdir -p "${CONFIG_DIR}"

    if [[ -f "${cfg}" ]]; then
        if ! confirm "检测到已有配置，是否覆盖？" "n"; then
            warn "已取消初始化配置"
            return 0
        fi
        backup="${cfg}.bak.$(date +%Y%m%d%H%M%S)"
        cp -f "${cfg}" "${backup}"
        info "已备份旧配置到 ${backup}"
    fi

    while true; do
        core_type="$(prompt_text "选择内核类型(sing/xray/hysteria2)" "sing")"
        core_type="$(echo "${core_type}" | tr '[:upper:]' '[:lower:]')"
        if [[ "${core_type}" == "sing" || "${core_type}" == "xray" || "${core_type}" == "hysteria2" ]]; then
            break
        fi
        warn "仅支持 sing / xray / hysteria2"
    done

    api_host="$(prompt_text "面板地址 ApiHost" "http://127.0.0.1")"
    api_key="$(prompt_required_text "面板 API Key")"
    node_id="$(prompt_int "节点 ID NodeID" "1")"
    node_type="$(prompt_text "节点类型 NodeType(面板分类)" "v2ray")"
    timeout="$(prompt_int "接口超时(秒)" "30")"
    listen_ip="$(prompt_text "监听 IP ListenIP" "0.0.0.0")"
    send_ip="$(prompt_text "发送 IP SendIP" "0.0.0.0")"
    cert_mode="$(prompt_text "证书模式 CertMode(self/file/dns)" "self")"
    while true; do
        transport="$(prompt_text "传输方式 Transport(http/grpc)" "http")"
        transport="$(echo "${transport}" | tr '[:upper:]' '[:lower:]')"
        if [[ "${transport}" == "http" || "${transport}" == "grpc" ]]; then
            break
        fi
        warn "仅支持 http / grpc"
    done

    grpc_json=""
    if [[ "${transport}" == "grpc" ]]; then
        grpc_host="$(prompt_text "GRPCHost(host:port，留空将从 ApiHost 推导)" "")"
        if confirm "是否启用 GRPCUseTLS (y/n)?" "y"; then
            grpc_use_tls=true
        else
            grpc_use_tls=false
        fi
        grpc_server_name="$(prompt_text "GRPCServerName(可为空，默认取主机名)" "")"
        grpc_keepalive="$(prompt_int "GRPCKeepalive(秒)" "30")"
        grpc_json=$(cat <<EOF
      "GRPCHost": "$(json_escape "${grpc_host}")",
      "GRPCUseTLS": ${grpc_use_tls},
      "GRPCServerName": "$(json_escape "${grpc_server_name}")",
      "GRPCKeepalive": ${grpc_keepalive},
EOF
)
    fi

    case "${core_type}" in
        sing)
            core_json='{
      "Type": "sing",
      "Log": {
        "Level": "info",
        "Timestamp": true
      },
      "NTP": {
        "Enable": false,
        "Server": "time.apple.com",
        "ServerPort": 0
      }
    }'
            ;;
        xray)
            core_json='{
      "Type": "xray"
    }'
            ;;
        hysteria2)
            core_json='{
      "Type": "hysteria2"
    }'
            ;;
    esac

    cat >"${cfg}" <<EOF
{
  "Log": {
    "Level": "info",
    "Output": ""
  },
  "Cores": [
    ${core_json}
  ],
  "Nodes": [
    {
      "Core": "$(json_escape "${core_type}")",
      "ApiHost": "$(json_escape "${api_host}")",
      "Transport": "$(json_escape "${transport}")",
${grpc_json}      "ApiKey": "$(json_escape "${api_key}")",
      "NodeID": ${node_id},
      "NodeType": "$(json_escape "${node_type}")",
      "Timeout": ${timeout},
      "ListenIP": "$(json_escape "${listen_ip}")",
      "SendIP": "$(json_escape "${send_ip}")",
      "DeviceOnlineMinTraffic": 200,
      "MinReportTraffic": 0,
      "CertConfig": {
        "CertMode": "$(json_escape "${cert_mode}")"
      }
    }
  ]
}
EOF

    chmod 600 "${cfg}" || true
    info "配置初始化完成: ${cfg}"
    info "默认仍使用: ${BIN_PATH} server -c ${cfg}"
}

uninstall_v2bx() {
    local purge_config="false"
    if [[ "${1:-}" == "--purge" ]]; then
        purge_config="true"
    fi

    warn "开始卸载 V2bX..."
    svc_stop >/dev/null 2>&1 || true
    svc_disable

    if is_alpine; then
        rm -f /etc/init.d/${SERVICE_NAME}
    else
        rm -f /etc/systemd/system/${SERVICE_NAME}.service
        systemctl daemon-reload || true
    fi

    rm -rf "${INSTALL_DIR}"
    rm -f "/usr/bin/${CMD_NAME}" "/usr/local/bin/${CMD_NAME}"

    if [[ "${purge_config}" == "true" ]]; then
        rm -rf "${CONFIG_DIR}"
        info "已删除程序目录和配置目录"
    else
        info "已删除程序目录，保留配置目录：${CONFIG_DIR}"
    fi
}

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local answer

    read -r -p "${prompt} [${default}]: " answer
    answer="${answer:-${default}}"
    [[ "${answer}" == "y" || "${answer}" == "Y" ]]
}

pause_return() {
    echo
    read -r -p "按回车返回主菜单..." _
}

print_service_summary() {
    local rstate estate
    rstate="$(run_state)"
    estate="$(enable_state)"

    echo -e "安装状态: $(install_state_label "${rstate}")"
    echo -e "运行状态: $(state_label "${rstate}")"
    echo -e "开机自启: $(state_label "${estate}")"
}

show_help() {
    cat <<EOF
V2bX 管理脚本

无参数运行时进入可视化菜单。

Usage:
  ${CMD_NAME}                     # 进入菜单
  ${CMD_NAME} menu                # 进入菜单
  ${CMD_NAME} initconfig
  ${CMD_NAME} start
  ${CMD_NAME} stop
  ${CMD_NAME} restart
  ${CMD_NAME} status
  ${CMD_NAME} enable
  ${CMD_NAME} disable
  ${CMD_NAME} log
  ${CMD_NAME} config
  ${CMD_NAME} update [version]
  ${CMD_NAME} install [version]
  ${CMD_NAME} uninstall [--purge]
  ${CMD_NAME} version
  ${CMD_NAME} x25519
  ${CMD_NAME} generate
EOF
}

menu_header() {
    clear || true
    echo -e "${cyan}========================================${plain}"
    echo -e "${cyan}              V2bX 管理菜单${plain}"
    echo -e "${cyan}========================================${plain}"
    print_service_summary
    echo
    echo " 1. 启动 V2bX"
    echo " 2. 停止 V2bX"
    echo " 3. 重启 V2bX"
    echo " 4. 查看状态"
    echo " 5. 查看日志"
    echo " 6. 启用开机自启"
    echo " 7. 关闭开机自启"
    echo " 8. 编辑配置文件"
    echo " 9. 更新到最新版本"
    echo "10. 更新到指定版本"
    echo "11. 安装/重装 V2bX"
    echo "12. 卸载 V2bX（保留配置）"
    echo "13. 卸载 V2bX（删除配置）"
    echo "14. 初始化配置向导"
    echo "15. 生成 x25519 密钥"
    echo "16. 生成配置模板"
    echo "17. 查看版本"
    echo " 0. 退出"
    echo
}

run_menu() {
    local choice version
    while true; do
        menu_header
        read -r -p "请输入选项 [0-17]: " choice
        case "${choice}" in
            1) execute_command "start" || true ;;
            2) execute_command "stop" || true ;;
            3) execute_command "restart" || true ;;
            4) execute_command "status" || true ;;
            5) execute_command "log" || true ;;
            6) execute_command "enable" || true ;;
            7) execute_command "disable" || true ;;
            8) execute_command "config" || true ;;
            9) execute_command "update" || true ;;
            10)
                read -r -p "请输入版本号（如 v0.0.1）: " version
                if [[ -z "${version}" ]]; then
                    warn "未输入版本号，已取消"
                else
                    execute_command "update" "${version}" || true
                fi
                ;;
            11) execute_command "install" || true ;;
            12)
                if confirm "确认卸载（保留配置）？" "n"; then
                    execute_command "uninstall" || true
                fi
                ;;
            13)
                if confirm "确认彻底卸载（删除配置）？" "n"; then
                    execute_command "uninstall" "--purge" || true
                fi
                ;;
            14) execute_command "initconfig" || true ;;
            15) execute_command "x25519" || true ;;
            16) execute_command "generate" || true ;;
            17) execute_command "version" || true ;;
            0) exit 0 ;;
            *)
                warn "无效选项：${choice}"
                ;;
        esac
        pause_return
    done
}

execute_command() {
    local cmd="$1"
    shift || true

    case "${cmd}" in
        start)
            if ! is_installed; then
                error "V2bX 未安装"
                return 1
            fi
            svc_start
            info "已执行启动"
            ;;
        stop)
            if ! is_installed; then
                error "V2bX 未安装"
                return 1
            fi
            svc_stop
            info "已执行停止"
            ;;
        restart)
            if ! is_installed; then
                error "V2bX 未安装"
                return 1
            fi
            svc_restart
            info "已执行重启"
            ;;
        status)
            svc_status
            ;;
        enable)
            svc_enable
            info "已启用开机自启"
            ;;
        disable)
            svc_disable
            info "已关闭开机自启"
            ;;
        log)
            show_log
            ;;
        config)
            edit_config
            ;;
        initconfig)
            init_config_wizard
            ;;
        install)
            run_install_script "${1:-}"
            ;;
        update)
            run_install_script "${1:-}"
            ;;
        uninstall)
            uninstall_v2bx "${1:-}"
            ;;
        version)
            run_bin_subcommand "version" "$@" || run_bin_subcommand "--version" "$@"
            ;;
        x25519|generate)
            run_bin_subcommand "${cmd}" "$@"
            ;;
        menu)
            run_menu
            ;;
        *)
            error "未知命令: ${cmd}"
            return 1
            ;;
    esac
}

main() {
    local cmd="${1:-menu}"
    shift || true

    if [[ "${cmd}" == "help" || "${cmd}" == "-h" || "${cmd}" == "--help" ]]; then
        show_help
        exit 0
    fi

    need_root

    if [[ "${cmd}" == "menu" ]]; then
        run_menu
        exit 0
    fi

    execute_command "${cmd}" "$@"
}

main "$@"
