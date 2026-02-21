# Docker build arguments
ARG DOTNET_VERSION=10.0
ARG NODEJS_VERSION=24

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build the Web Client (matches the official jellyfin-packaging setup)
# ─────────────────────────────────────────────────────────────────────────────
FROM node:${NODEJS_VERSION}-alpine AS web

ARG SOURCE_DIR=/src
ARG ARTIFACT_DIR=/web

RUN apk add --no-cache \
    autoconf \
    automake \
    g++ \
    gcc \
    git \
    libtool \
    make \
    musl-dev \
    nasm \
    python3 \
 && git config --global --add safe.directory /jellyfin/jellyfin-web

WORKDIR ${SOURCE_DIR}
COPY jellyfin-web .

RUN npm ci --no-audit --unsafe-perm \
 && npm run build:production \
 && mv dist ${ARTIFACT_DIR}

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Build the Server
# Using the official .NET SDK image is more reliable than running
# dotnet-install.sh on a plain Debian/Ubuntu base.
# ─────────────────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS server

ARG SOURCE_DIR=/src
ARG ARTIFACT_DIR=/server

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

WORKDIR ${SOURCE_DIR}
COPY . .

RUN dotnet publish Jellyfin.Server \
    --configuration Release \
    --output="${ARTIFACT_DIR}" \
    --self-contained false \
    -p:DebugSymbols=false \
    -p:DebugType=none

# ─────────────────────────────────────────────────────────────────────────────
# Stage 3: Final image
# ASP.NET runtime image (Ubuntu 24.04 Noble) includes the .NET runtime.
# jellyfin-ffmpeg is installed from the official Jellyfin apt repository.
# Hardware acceleration drivers (Intel OpenCL, Rockchip Mali) are omitted
# as this image is intended for functional testing.
# ─────────────────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION}

# Set the health URL
ENV HEALTHCHECK_URL=http://localhost:8096/health

# Default environment variables for the Jellyfin invocation
ENV DEBIAN_FRONTEND="noninteractive" \
    LC_ALL="en_US.UTF-8" \
    LANG="en_US.UTF-8" \
    LANGUAGE="en_US:en" \
    JELLYFIN_DATA_DIR="/config" \
    JELLYFIN_CACHE_DIR="/cache" \
    JELLYFIN_CONFIG_DIR="/config/config" \
    JELLYFIN_LOG_DIR="/config/log" \
    JELLYFIN_WEB_DIR="/jellyfin/jellyfin-web" \
    JELLYFIN_FFMPEG="/usr/lib/jellyfin-ffmpeg/ffmpeg"

# Install base dependencies, then add the Jellyfin apt repo and install
# jellyfin-ffmpeg from it. Using the same repo/codename as the official image.
RUN apt-get update \
 && apt-get install --no-install-recommends --no-install-suggests --yes \
    ca-certificates \
    curl \
    gnupg \
    locales \
    libfontconfig1 \
    libfreetype6 \
 && sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
 && locale-gen \
 # Add Jellyfin apt repository (targeting Ubuntu 24.04 Noble — matches base image)
 && curl -fsSL https://repo.jellyfin.org/jellyfin_team.gpg.key \
      | gpg --dearmor -o /etc/apt/trusted.gpg.d/jellyfin.gpg \
 && echo "deb [arch=$( dpkg --print-architecture )] https://repo.jellyfin.org/ubuntu noble main" \
      > /etc/apt/sources.list.d/jellyfin.list \
 && apt-get update \
 && apt-get install --no-install-recommends --no-install-suggests --yes \
    jellyfin-ffmpeg7 \
 && apt-get clean autoclean --yes \
 && apt-get autoremove --yes \
 && rm -rf /var/cache/apt/archives* /var/lib/apt/lists/*

RUN mkdir -p ${JELLYFIN_DATA_DIR} ${JELLYFIN_CACHE_DIR} \
 && chmod 777 ${JELLYFIN_DATA_DIR} ${JELLYFIN_CACHE_DIR}

COPY --from=server /server /jellyfin
COPY --from=web /web /jellyfin/jellyfin-web

EXPOSE 8096
VOLUME ${JELLYFIN_DATA_DIR} ${JELLYFIN_CACHE_DIR}

ENTRYPOINT ["/jellyfin/jellyfin"]

HEALTHCHECK --interval=30s --timeout=30s --start-period=10s --retries=3 \
    CMD curl --noproxy 'localhost' -Lk -fsS "${HEALTHCHECK_URL}" || exit 1
