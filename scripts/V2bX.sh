#!/usr/bin/env bash

set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

REPO_OWNER="${REPO_OWNER:-AnixOps}"
REPO_NAME="${REPO_NAME:-V2bX_AnixOps}"
REPO_BRANCH="${REPO_BRANCH:-dev_new}"

SERVICE_NAME="V2bX"
INSTALL_DIR="/usr/local/V2bX"
BIN_PATH="${INSTALL_DIR}/V2bX"
CONFIG_DIR="/etc/V2bX"
INSTALL_SCRIPT_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}/scripts/install.sh"

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
        rc-update add "${SERVICE_NAME}" default
    else
        systemctl enable "${SERVICE_NAME}"
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
    local tmp_file
    local rc=0
    tmp_file="$(mktemp)"

    curl -fsSL "${INSTALL_SCRIPT_URL}" -o "${tmp_file}"
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

    if [[ ! -x "${BIN_PATH}" ]]; then
        error "未检测到可执行文件：${BIN_PATH}"
        exit 1
    fi

    "${BIN_PATH}" "${sub_cmd}" "$@"
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
        systemctl daemon-reload
    fi

    rm -rf "${INSTALL_DIR}"
    rm -f /usr/bin/V2bX /usr/bin/v2bx

    if [[ "${purge_config}" == "true" ]]; then
        rm -rf "${CONFIG_DIR}"
        info "已删除程序目录和配置目录"
    else
        info "已删除程序目录，保留配置目录：${CONFIG_DIR}"
    fi
}

show_help() {
    cat <<'EOF'
V2bX 管理脚本

Usage:
  V2bX start
  V2bX stop
  V2bX restart
  V2bX status
  V2bX enable
  V2bX disable
  V2bX log
  V2bX update [version]
  V2bX install [version]
  V2bX uninstall [--purge]
  V2bX version
  V2bX x25519
  V2bX generate
EOF
}

main() {
    local cmd="${1:-help}"
    shift || true

    if [[ "${cmd}" == "help" || "${cmd}" == "-h" || "${cmd}" == "--help" ]]; then
        show_help
        exit 0
    fi

    need_root

    case "${cmd}" in
        start)
            svc_start
            ;;
        stop)
            svc_stop
            ;;
        restart)
            svc_restart
            ;;
        status)
            svc_status
            ;;
        enable)
            svc_enable
            ;;
        disable)
            svc_disable
            ;;
        log)
            show_log
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
        *)
            error "未知命令: ${cmd}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
