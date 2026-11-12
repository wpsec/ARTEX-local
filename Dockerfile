# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/artex。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地镜像构建请先用 build.sh 编译匹配架构的二进制，再按 README 的 Compose 命令构建。
ARG ZAP_VERSION=2.17.0
FROM ghcr.io/zaproxy/zaproxy:${ZAP_VERSION} AS zap-runtime
ARG ZAP_VERSION=2.17.0
ARG ZAP_MCP_ADDON_VERSION=0.4.0
RUN zap.sh -cmd -silent -addoninstall mcp \
    && installed_addons="$(zap.sh -cmd -silent -addonlist)" \
    && printf '%s\n' "$installed_addons" \
      | grep -Eiq "mcp.*${ZAP_MCP_ADDON_VERSION}|${ZAP_MCP_ADDON_VERSION}.*mcp" \
    && cp /home/zap/.ZAP/plugin/*.zap /zap/plugin/ \
    && cp /usr/share/common-licenses/Apache-2.0 /zap/ApacheLicense-2.0.txt \
    && curl -fsSL "https://raw.githubusercontent.com/zaproxy/zaproxy/v${ZAP_VERSION}/LEGALNOTICE.md" -o /zap/LEGALNOTICE.md

FROM ghcr.io/zaproxy/zaproxy:${ZAP_VERSION} AS web-tools
USER root
ARG TARGETARCH
ARG FFUF_VERSION=2.3.0
ARG SQLMAP_COMMIT=eca9ff2e134f66a69fa64b1715b9cfcf9a1164bc
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) ffuf_sha256=b2a3c725fcb9da175159682f54d6e9149f2905b00d84d155e7efc5d599975ceb ;; \
      arm64) ffuf_sha256=e2d712615d53da797ee929006e41f2df5a7960a5353133db9c150ddaa22ae4e8 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    ffuf_archive="ffuf_${FFUF_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    curl --retry 5 --retry-all-errors --retry-delay 2 -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/${ffuf_archive}" -o "/tmp/${ffuf_archive}"; \
    echo "${ffuf_sha256}  /tmp/${ffuf_archive}" | sha256sum -c -; \
    mkdir -p /tmp/ffuf; \
    tar -xzf "/tmp/${ffuf_archive}" -C /tmp/ffuf ffuf; \
    install -D -m 0755 /tmp/ffuf/ffuf /out/usr/local/bin/ffuf; \
    mkdir -p /out/usr/share/doc/ffuf; \
    curl --retry 5 --retry-all-errors --retry-delay 2 -fsSL "https://raw.githubusercontent.com/ffuf/ffuf/v${FFUF_VERSION}/LICENSE" -o /out/usr/share/doc/ffuf/copyright
RUN set -eux; \
    mkdir -p /out/opt/sqlmap; \
    curl --retry 5 --retry-all-errors --retry-delay 2 -fsSL "https://github.com/sqlmapproject/sqlmap/archive/${SQLMAP_COMMIT}.tar.gz" -o /tmp/sqlmap.tar.gz; \
    tar -xzf /tmp/sqlmap.tar.gz --strip-components=1 -C /out/opt/sqlmap; \
    chmod 0755 /out/opt/sqlmap/sqlmap.py; \
    mkdir -p /out/usr/local/bin; \
    printf '%s\n' '#!/bin/sh' 'exec python3 /opt/sqlmap/sqlmap.py "$@"' > /out/usr/local/bin/sqlmap; \
    chmod 0755 /out/usr/local/bin/sqlmap

FROM python:3.12-slim-bookworm
ARG TARGETARCH
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
      openjdk-17-jre-headless \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
RUN npm install -g puppeteer-core@23.11.1 \
    && chromium_path="$(NODE_PATH="$(npm root -g)" node -e 'process.stdout.write(require("playwright").chromium.executablePath())')" \
    && ln -sf "$chromium_path" /usr/bin/chromium
COPY --from=zap-runtime /zap /opt/zap
COPY --from=zap-runtime /zap/ApacheLicense-2.0.txt /usr/share/doc/puppeteer-core/LICENSE
COPY --from=web-tools /out/ /
COPY tools/ffuf/web-common.txt /opt/artex/wordlists/web-common.txt
ENV NODE_PATH="/usr/lib/node_modules"
ENV PATH="/opt/zap:${PATH}"
WORKDIR /app
COPY THIRD_PARTY_NOTICES.md /app/THIRD_PARTY_NOTICES.md
# 预编译好的对应架构二进制（dist/amd64/artex 或 dist/arm64/artex）
COPY dist/${TARGETARCH}/artex /app/artex
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
ARG ARTEX_VERSION=dev
LABEL org.opencontainers.image.version="${ARTEX_VERSION}"
