# =============================================================================
# AIGuardFabric 多阶段构建（cargo-chef 依赖缓存 + distroless 运行时）
#
# 目标（§9 构建）：
#   * 依赖层与源码层分离，增量构建不重复编译依赖
#   * 构建缓存写 <项目>/.cargo/（铁律 2：不污染系统盘）
#   * 运行时镜像 <100MB/服务，非 root（uid 10001），只读根文件系统
#
# 构建示例：
#   docker build -f deploy/docker/Dockerfile --target server -t agf-server:0.1.0 .
#   docker build -f deploy/docker/Dockerfile --target web    -t agf-web:0.1.0 .
# =============================================================================

ARG RUST_VERSION=1.97
ARG NODE_VERSION=24

# ---------------------------------------------------------------------------
# 1. planner：用 cargo-chef 生成依赖配方（recipe.json）
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim AS planner

WORKDIR /app
# 项目内缓存重定向（与 compose 中的 CARGO_HOME 保持一致）
ARG AGF_BUILD_CACHE_DIR=/app/.cargo
ENV CARGO_HOME=${AGF_BUILD_CACHE_DIR} \
    CARGO_TARGET_DIR=/app/target

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev cmake clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked --version ^0.1

# The pinned rust base image already contains the compiler. Copying the host's
# "stable" override would make rustup query the network during offline builds.
COPY Cargo.toml Cargo.lock ./
COPY vendor/yara-x ./vendor/yara-x
COPY crates ./crates
COPY apps ./apps
COPY tests/fixtures/alicloud ./tests/fixtures/alicloud
# workspace 成员之一（本地 mTLS 终结器）：`cargo metadata` 需要它的 manifest 才能解析整个
# workspace，缺了就报 "failed to load manifest for workspace member ... No such file or directory"。
COPY tools/simulators/agf-mtls-terminator ./tools/simulators/agf-mtls-terminator
RUN cargo chef prepare --recipe-path recipe.json

# ---------------------------------------------------------------------------
# 2. builder：编译依赖（缓存命中层）+ 编译业务代码
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim AS builder

WORKDIR /app
ARG AGF_BUILD_CACHE_DIR=/app/.cargo
ENV CARGO_HOME=${AGF_BUILD_CACHE_DIR} \
    CARGO_TARGET_DIR=/app/target \
    CARGO_NET_RETRY=10 \
    RUST_BACKTRACE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev cmake clang libclang-dev protobuf-compiler xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked --version ^0.1

COPY --from=planner /app/recipe.json recipe.json
COPY vendor/yara-x ./vendor/yara-x
# Both planner and builder use the same pinned rust base image and its default toolchain.
# 依赖层：源码变化不影响该层缓存。
RUN --mount=type=cache,id=agf-rust-release-v1,target=/app/target,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY vendor/yara-x ./vendor/yara-x
COPY crates ./crates
COPY apps ./apps
COPY tests/fixtures/alicloud ./tests/fixtures/alicloud
COPY tests/fixtures/logs ./tests/fixtures/logs
# 同上：workspace 成员必须存在，否则 `cargo build --release` 解析 workspace 失败
COPY tools/simulators/agf-mtls-terminator ./tools/simulators/agf-mtls-terminator
COPY deploy ./deploy
# 规则库与红队用例库要打进运行镜像（离线可用；compose/k8s 也可用只读卷覆盖为最新版）
COPY rules ./rules
COPY redteam ./redteam
# 厂商日志解析模板库（§4.5 内置 100+ 模板）：ingest/server 运行时按 /app/parsers 加载，可用 AGF_PARSERS_DIR 覆盖
COPY parsers ./parsers

# 构建三个二进制（server / ingest / scheduler 同属 workspace，一次编译产出全部）
RUN --mount=type=cache,id=agf-rust-release-v1,target=/app/target,sharing=locked \
    cargo build --release --locked --bins \
    && mkdir -p /out \
    && for bin in agf-server agf-ingest agf-scheduler agfctl agf-agent; do \
         if [ -f "target/release/${bin}" ]; then cp "target/release/${bin}" /out/; fi; \
       done \
    && ls -lh /out

# ---------------------------------------------------------------------------
# 3a. server / ingest / scheduler 运行镜像
#     distroless：无 shell、无包管理器，最小攻击面
#
# ⚠️ glibc 版本必须与 builder 匹配：`rust:1.97-slim` 基于 Debian **13 (trixie)**，
# 产物依赖 GLIBC_2.38；而 distroless 的 `cc-debian12` 是 Debian 12（glibc 2.36），
# 实测启动直接报 `version 'GLIBC_2.38' not found` 而退出。因此运行镜像必须用
# `cc-debian13`。改动 builder 的基础镜像时，这里必须同步改（反之亦然）。
# ---------------------------------------------------------------------------
# 仅压缩 server ELF；使用原版官方工具与固定校验和，Agent 保持原字节。
FROM builder AS packed-server
ADD --checksum=sha256:402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657 https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-amd64_linux.tar.xz /tmp/upx-5.2.1-amd64_linux.tar.xz
RUN printf '%s  %s\n' '402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657' /tmp/upx-5.2.1-amd64_linux.tar.xz | sha256sum -c - \
    && mkdir -p /tmp/upx-tool /packed /packer-licenses \
    && tar -xJf /tmp/upx-5.2.1-amd64_linux.tar.xz -C /tmp/upx-tool \
    && /tmp/upx-tool/upx-5.2.1-amd64_linux/upx --best --lzma --no-progress --no-env -o /packed/agf-server /out/agf-server \
    && /tmp/upx-tool/upx-5.2.1-amd64_linux/upx --no-env -t /packed/agf-server \
    && /tmp/upx-tool/upx-5.2.1-amd64_linux/upx --no-env -d -o /tmp/agf-server-restored /packed/agf-server \
    && cmp /out/agf-server /tmp/agf-server-restored \
    && cp /tmp/upx-tool/upx-5.2.1-amd64_linux/LICENSE /packer-licenses/UPX-LICENSE.txt \
    && cp /tmp/upx-tool/upx-5.2.1-amd64_linux/COPYING /packer-licenses/UPX-COPYING.txt
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime-base

WORKDIR /app
ENV AGF_ENV=prod \
    AGF_PROJECT_ROOT=/app \
    AGF_DATA_DIR=/data \
    AGF_SERVER_HOST=0.0.0.0 \
    AGF_SERVER_PORT=8080 \
    RUST_LOG=info

# distroless nonroot 用户 uid=65532；为与 compose 的 10001 对齐，这里显式声明
USER 10001:10001
EXPOSE 8080 8090 8091 9100 9101 5514

FROM runtime-base AS server
COPY --from=packed-server /packed/agf-server /usr/local/bin/agf-server
COPY --from=builder /out/agf-agent /app/dist/linux/agf-agent
COPY --from=builder /app/crates/agf-api/resources/fonts/OFL.txt /app/licenses/NotoSansCJKsc-OFL.txt
COPY --from=packed-server /packer-licenses/UPX-LICENSE.txt /app/licenses/UPX-LICENSE.txt
COPY --from=packed-server /packer-licenses/UPX-COPYING.txt /app/licenses/UPX-COPYING.txt
LABEL org.aiguardfabric.packer.version="UPX 5.2.1 unmodified official amd64 Linux"
LABEL org.aiguardfabric.font.noto-cjk.source="https://raw.githubusercontent.com/notofonts/noto-cjk/Sans2.004/Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf" \
      org.aiguardfabric.font.noto-cjk.license="SIL OFL 1.1"
COPY --from=builder /app/deploy/sql/migrations /app/deploy/sql/migrations
COPY --from=builder /app/deploy/sql/migration_parts /app/deploy/sql/migration_parts
COPY --from=builder /app/rules /app/rules
# 红队用例库与解析模板库：server 端 `/readyz` 与 /redteam/cases、/parsers 端点直接消费
COPY --from=builder /app/redteam /app/redteam
COPY --from=builder /app/parsers /app/parsers
COPY --from=builder /app/tests/fixtures/logs /app/tests/fixtures/logs
ENTRYPOINT ["/usr/local/bin/agf-server"]

FROM runtime-base AS ingest
COPY --from=builder /out/agf-ingest /usr/local/bin/agf-ingest
COPY --from=builder /app/rules /app/rules
COPY --from=builder /app/parsers /app/parsers
ENTRYPOINT ["/usr/local/bin/agf-ingest"]

FROM runtime-base AS scheduler
COPY --from=builder /out/agf-scheduler /usr/local/bin/agf-scheduler
COPY --from=builder /out/agfctl /usr/local/bin/agfctl
COPY --from=builder /app/rules /app/rules
COPY --from=builder /app/redteam /app/redteam
COPY --from=builder /app/parsers /app/parsers
ENTRYPOINT ["/usr/local/bin/agf-scheduler"]

# ---------------------------------------------------------------------------
# 3b. builder-web：编译 React 控制台
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-slim AS builder-web

WORKDIR /app/apps/web
ENV PNPM_HOME=/app/.pnpm \
    npm_config_store_dir=/app/.pnpm-store \
    CI=true

RUN corepack enable && corepack prepare pnpm@11 --activate

# 依赖层
# `pnpm-workspace.yaml` 必须一起进依赖层：它声明了 allowBuilds 与
# minimumReleaseAgeExclude（esbuild/@tanstack/jsdom 三个新发布版本的豁免），
# 少了它 pnpm 会以 ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION 中止安装。
COPY apps/web/package.json apps/web/pnpm-lock.yaml apps/web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --prefer-offline

# 源码层
COPY apps/web ./
RUN pnpm run build

# ---------------------------------------------------------------------------
# 3c. web 运行镜像：nginx 非 root（unprivileged 变体）
# ---------------------------------------------------------------------------
FROM nginxinc/nginx-unprivileged:1.27-alpine AS web

USER 10001:10001
COPY --from=builder-web /app/apps/web/dist /usr/share/nginx/html
COPY deploy/docker/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
    CMD wget -q -O - http://127.0.0.1:8080/ >/dev/null || exit 1
