#!/usr/bin/env bash

set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

REPO_OWNER="${REPO_OWNER:-AnixOps}"
REPO_NAME="${REPO_NAME:-V2bX_AnixOps}"
REPO_BRANCH="${REPO_BRANCH:-dev_new}"

APP_NAME="V2bX"
SERVICE_NAME="V2bX"
INSTALL_DIR="/usr/local/${APP_NAME}"
CONFIG_DIR="/etc/${APP_NAME}"
BIN_PATH="${INSTALL_DIR}/${APP_NAME}"

API_BASE="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"
RELEASE_BASE="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download"
RAW_SCRIPT_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}/scripts/V2bX.sh"

release=""
tmp_dir=""

cleanup() {
    if [[ -n "${tmp_dir}" && -d "${tmp_dir}" ]]; then
        rm -rf "${tmp_dir}"
    fi
}

trap cleanup EXIT

info() {
    echo -e "${green}$*${plain}" >&2
}

warn() {
    echo -e "${yellow}$*${plain}" >&2
}

error() {
    echo -e "${red}$*${plain}" >&2
}

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "错误：必须使用 root 用户运行此脚本"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/alpine-release ]]; then
        release="alpine"
        return
    fi

    if command -v apt-get >/dev/null 2>&1; then
        release="debian"
        return
    fi

    if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        release="centos"
        return
    fi

    if command -v pacman >/dev/null 2>&1; then
        release="arch"
        return
    fi

    error "未检测到受支持的系统（支持 Debian/Ubuntu/CentOS/Alpine/Arch）"
    exit 1
}

install_base() {
    info "安装基础依赖..."
    case "${release}" in
        centos)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y curl wget unzip tar ca-certificates >/dev/null 2>&1
            else
                yum install -y curl wget unzip tar ca-certificates >/dev/null 2>&1
            fi
            ;;
        debian)
            apt-get update -y >/dev/null 2>&1
            apt-get install -y curl wget unzip tar ca-certificates >/dev/null 2>&1
            ;;
        alpine)
            apk add --no-cache curl wget unzip tar ca-certificates >/dev/null 2>&1
            ;;
        arch)
            pacman -Sy --noconfirm --needed curl wget unzip tar ca-certificates >/dev/null 2>&1
            ;;
    esac
}

detect_asset_suffix() {
    local arch
    arch="$(uname -m)"

    case "${arch}" in
        x86_64|amd64)
            echo "linux-64"
            ;;
        i386|i486|i586|i686|x86)
            echo "linux-32"
            ;;
        aarch64|arm64)
            echo "linux-arm64-v8a"
            ;;
        armv7l|armv7)
            echo "linux-arm32-v7a"
            ;;
        armv6l|armv6)
            echo "linux-arm32-v6"
            ;;
        armv5tel|armv5)
            echo "linux-arm32-v5"
            ;;
        s390x)
            echo "linux-s390x"
            ;;
        riscv64)
            echo "linux-riscv64"
            ;;
        ppc64le)
            echo "linux-ppc64le"
            ;;
        ppc64)
            echo "linux-ppc64"
            ;;
        mips64el|mips64le)
            echo "linux-mips64le"
            ;;
        mips64)
            echo "linux-mips64"
            ;;
        mipsel|mipsle)
            echo "linux-mips32le"
            ;;
        mips)
            echo "linux-mips32"
            ;;
        *)
            return 1
            ;;
    esac
}

fetch_latest_release() {
    local tag
    tag="$(
        curl -fsSL \
            -H "Accept: application/vnd.github+json" \
            -H "User-Agent: ${APP_NAME}-installer" \
            "${API_BASE}/releases/latest" \
            | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
            | head -n 1
    )"

    if [[ -z "${tag}" ]]; then
        error "获取 latest release 失败，请先在 ${REPO_OWNER}/${REPO_NAME} 创建 Release，或手动指定版本"
        exit 1
    fi

    echo "${tag}"
}

download_release_zip() {
    local version="$1"
    local asset_suffix="$2"
    local asset_name="V2bX-${asset_suffix}.zip"
    local download_url="${RELEASE_BASE}/${version}/${asset_name}"
    local zip_path="${tmp_dir}/${asset_name}"

    info "下载 ${asset_name} (${version})..."
    if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 600 \
        "${download_url}" -o "${zip_path}"; then
        error "下载失败：${download_url}"
        error "请确认该版本已发布且包含此架构资产"
        exit 1
    fi

    echo "${zip_path}"
}

install_files() {
    local zip_path="$1"
    local extract_dir="${tmp_dir}/extract"

    mkdir -p "${extract_dir}"
    unzip -oq "${zip_path}" -d "${extract_dir}"

    if [[ ! -f "${extract_dir}/V2bX" ]]; then
        error "压缩包中未找到 V2bX 可执行文件"
        exit 1
    fi

    mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}"

    install -m 0755 "${extract_dir}/V2bX" "${BIN_PATH}"

    for f in geoip.dat geosite.dat; do
        if [[ -f "${extract_dir}/${f}" ]]; then
            install -m 0644 "${extract_dir}/${f}" "${CONFIG_DIR}/${f}"
        fi
    done

    for f in config.json dns.json route.json custom_outbound.json custom_inbound.json; do
        if [[ -f "${extract_dir}/${f}" && ! -f "${CONFIG_DIR}/${f}" ]]; then
            install -m 0644 "${extract_dir}/${f}" "${CONFIG_DIR}/${f}"
        fi
    done
}

install_service() {
    if [[ "${release}" == "alpine" ]]; then
        cat >/etc/init.d/${SERVICE_NAME} <<'EOF'
#!/sbin/openrc-run

name="V2bX"
description="V2bX Service"
command="/usr/local/V2bX/V2bX"
command_args="server -c /etc/V2bX/config.json"
command_user="root"
pidfile="/run/V2bX.pid"
command_background="yes"

depend() {
    need net
}
EOF
        chmod +x /etc/init.d/${SERVICE_NAME}
        rc-update add ${SERVICE_NAME} default >/dev/null 2>&1 || true
    else
        cat >/etc/systemd/system/${SERVICE_NAME}.service <<'EOF'
[Unit]
Description=V2bX Service
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/usr/local/V2bX/
ExecStart=/usr/local/V2bX/V2bX server -c /etc/V2bX/config.json
Restart=always
RestartSec=10
LimitNOFILE=512000

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable ${SERVICE_NAME} >/dev/null 2>&1 || true
    fi
}

install_manage_script() {
    info "安装管理脚本 /usr/bin/V2bX ..."
    curl -fsSL "${RAW_SCRIPT_URL}" -o /usr/bin/V2bX
    chmod +x /usr/bin/V2bX
    ln -sf /usr/bin/V2bX /usr/bin/v2bx
    # Ensure PATH-preferred /usr/local/bin also points to the menu wrapper.
    ln -sf /usr/bin/V2bX /usr/local/bin/V2bX
    ln -sf /usr/bin/V2bX /usr/local/bin/v2bx
}

restart_service() {
    if [[ "${release}" == "alpine" ]]; then
        rc-service ${SERVICE_NAME} restart >/dev/null 2>&1 || rc-service ${SERVICE_NAME} start >/dev/null 2>&1
        rc-service ${SERVICE_NAME} status || true
    else
        systemctl restart ${SERVICE_NAME}
        systemctl --no-pager --full status ${SERVICE_NAME} || true
    fi
}

print_help() {
    cat <<EOF
Usage:
  bash install.sh                # 安装最新版本
  bash install.sh v0.1.0         # 安装指定版本

环境变量（可选）:
  REPO_OWNER   默认: AnixOps
  REPO_NAME    默认: V2bX_AnixOps
  REPO_BRANCH  默认: dev_new
EOF
}

main() {
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        print_help
        exit 0
    fi

    if [[ $# -gt 1 ]]; then
        print_help
        exit 1
    fi

    need_root
    detect_os
    install_base

    local first_install=false
    if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
        first_install=true
    fi

    local version="${1:-}"
    if [[ -z "${version}" ]]; then
        version="$(fetch_latest_release)"
    fi

    local asset_suffix
    if ! asset_suffix="$(detect_asset_suffix)"; then
        error "不支持的系统架构：$(uname -m)"
        exit 1
    fi

    info "系统: ${release}, 架构资产: ${asset_suffix}, 版本: ${version}"

    tmp_dir="$(mktemp -d)"
    local zip_path
    zip_path="$(download_release_zip "${version}" "${asset_suffix}")"

    install_files "${zip_path}"
    install_service
    install_manage_script

    if [[ "${first_install}" == "true" ]]; then
        warn "检测到首次安装，已写入默认配置：${CONFIG_DIR}/config.json"
        warn "请先修改配置后再启动：V2bX start"
    else
        info "检测到已有配置，尝试重启服务..."
        restart_service
    fi

    echo
    info "安装完成。常用命令："
    echo "  V2bX start|stop|restart|status|log"
    echo "  V2bX update [version]"
    echo "  V2bX uninstall [--purge]"
}

main "$@"
