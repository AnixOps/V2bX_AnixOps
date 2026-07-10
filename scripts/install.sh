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
MANAGE_CMD_NAME="v2bx-anixops"

API_BASE="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"
RELEASE_BASE="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}"
VERSION_FILE="${INSTALL_DIR}/.release-version"

release=""
tmp_dir=""
backup_path=""

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
                dnf install -y coreutils curl wget unzip tar ca-certificates >/dev/null 2>&1
            else
                yum install -y coreutils curl wget unzip tar ca-certificates >/dev/null 2>&1
            fi
            ;;
        debian)
            apt-get update -y >/dev/null 2>&1
            apt-get install -y coreutils curl wget unzip tar ca-certificates >/dev/null 2>&1
            ;;
        alpine)
            apk add --no-cache coreutils curl wget unzip tar ca-certificates >/dev/null 2>&1
            ;;
        arch)
            pacman -Sy --noconfirm --needed coreutils curl wget unzip tar ca-certificates >/dev/null 2>&1
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
        aarch64|arm64)
            echo "linux-arm64-v8a"
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

validate_version() {
    local version="$1"
    if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
        error "版本号格式无效：${version}"
        exit 1
    fi
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

download_release_digest() {
    local release_version="$1"
    local asset_suffix="$2"
    local asset_name="V2bX-${asset_suffix}.zip"
    local digest_name="${asset_name}.dgst"
    local download_url="${RELEASE_BASE}/${release_version}/${digest_name}"
    local digest_path="${tmp_dir}/${digest_name}"

    info "下载 ${digest_name} (${release_version})..."
    curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 120 \
        "${download_url}" -o "${digest_path}"
    echo "${digest_path}"
}

verify_release_zip() {
    local zip_path="$1"
    local digest_path="$2"
    local expected actual

    expected="$(awk -F'= ' '/SHA(2-)?256/ { print $2; exit }' "${digest_path}" | tr -d '\r')"
    if [[ ! "${expected}" =~ ^[A-Fa-f0-9]{64}$ ]]; then
        error "校验文件中缺少 SHA-256：${digest_path}"
        exit 1
    fi
    actual="$(sha256sum "${zip_path}" | awk '{print $1}')"
    if [[ "${actual}" != "${expected}" ]]; then
        error "发行包 SHA-256 校验失败：${zip_path}"
        exit 1
    fi
    info "SHA-256 校验通过：$(basename "${zip_path}")"
}

backup_existing_binary() {
    if [[ ! -x "${BIN_PATH}" ]]; then
        return
    fi

    backup_path="${INSTALL_DIR}/backups/V2bX.$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$(dirname "${backup_path}")"
    cp -a "${BIN_PATH}" "${backup_path}"
    chmod 0700 "$(dirname "${backup_path}")" || true
    info "已备份旧二进制：${backup_path}"
}

restore_existing_binary() {
    if [[ -z "${backup_path}" || ! -f "${backup_path}" ]]; then
        return
    fi

    warn "启动失败，恢复旧二进制：${backup_path}"
    install -m 0755 "${backup_path}" "${BIN_PATH}"
}

install_files() {
    local zip_path="$1"
    local install_version="$2"
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

    printf '%s\n' "${install_version}" > "${VERSION_FILE}"
    chmod 0644 "${VERSION_FILE}"
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
    local install_version="$1"
    local raw_script_url="${RAW_BASE}/${install_version}/scripts/V2bX.sh"

    info "安装管理脚本 /usr/bin/${MANAGE_CMD_NAME} ..."
    curl -fsSL "${raw_script_url}" -o /usr/bin/${MANAGE_CMD_NAME}
    chmod +x /usr/bin/${MANAGE_CMD_NAME}
    # Ensure PATH-preferred /usr/local/bin points to the AnixOps wrapper.
    ln -sf /usr/bin/${MANAGE_CMD_NAME} /usr/local/bin/${MANAGE_CMD_NAME}
}

restart_service() {
    if [[ "${release}" == "alpine" ]]; then
        if ! rc-service ${SERVICE_NAME} restart >/dev/null 2>&1; then
            rc-service ${SERVICE_NAME} start >/dev/null 2>&1 || return 1
        fi
        rc-service ${SERVICE_NAME} status || true
        rc-service ${SERVICE_NAME} status >/dev/null 2>&1
    else
        if ! systemctl restart ${SERVICE_NAME}; then
            systemctl --no-pager --full status ${SERVICE_NAME} || true
            return 1
        fi
        systemctl --no-pager --full status ${SERVICE_NAME} || true
        systemctl is-active --quiet ${SERVICE_NAME}
    fi
}

print_help() {
    cat <<EOF
Usage:
  bash install.sh                # 安装最新版本
  bash install.sh v0.1.0         # 安装指定版本

安装器只下载 GitHub Release 资产，不会克隆仓库或在节点机执行本地构建。
安装指定稳定版本时会校验发布包 SHA-256，并保留旧二进制到
/usr/local/V2bX/backups/ 以便服务启动失败时自动恢复。

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
    command -v sha256sum >/dev/null 2>&1 || {
        error "未找到 sha256sum，无法验证 GitHub Release 资产"
        exit 1
    }

    local first_install=false
    if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
        first_install=true
    fi

    local version="${1:-}"
    if [[ -z "${version}" ]]; then
        version="$(fetch_latest_release)"
    fi
    validate_version "${version}"

    local asset_suffix
    if ! asset_suffix="$(detect_asset_suffix)"; then
        error "不支持的系统架构：$(uname -m)"
        exit 1
    fi

    info "系统: ${release}, 架构资产: ${asset_suffix}, 版本: ${version}"

    tmp_dir="$(mktemp -d)"
    local zip_path digest_path
    zip_path="$(download_release_zip "${version}" "${asset_suffix}")"
    digest_path="$(download_release_digest "${version}" "${asset_suffix}")"
    verify_release_zip "${zip_path}" "${digest_path}"

    backup_existing_binary
    install_files "${zip_path}" "${version}"
    install_service
    install_manage_script "${version}"

    if [[ "${first_install}" == "true" ]]; then
        warn "检测到首次安装，已写入默认配置：${CONFIG_DIR}/config.json"
        warn "请先修改配置后再启动：${MANAGE_CMD_NAME} start"
    else
        info "检测到已有配置，尝试重启服务..."
        if ! restart_service; then
            restore_existing_binary
            restart_service || true
            error "新版本启动失败，已恢复旧二进制。请检查：journalctl -u ${SERVICE_NAME} -n 200 --no-pager"
            exit 1
        fi
    fi

    echo
    info "安装完成。常用命令："
    echo "  ${MANAGE_CMD_NAME} start|stop|restart|status|log"
    echo "  ${MANAGE_CMD_NAME} initconfig"
    echo "  ${MANAGE_CMD_NAME} update [version]"
    echo "  ${MANAGE_CMD_NAME} uninstall [--purge]"
}

main "$@"
