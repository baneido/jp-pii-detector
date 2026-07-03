# syntax=docker/dockerfile:1
# jp-pii-detect のコンテナイメージ。GitLab CI / CircleCI / Bitbucket Pipelines /
# Jenkins など GitHub Actions 以外の CI からも `image:` 指定だけで使えるようにする。
# release ワークフローが ghcr.io/baneido/jp-pii-detector として
# linux/amd64 + linux/arm64 のマルチアーキテクチャで公開する（docs/integrations.md 参照）。

# ビルダーはビルドホストのアーキテクチャで動かし、Go のクロスコンパイルで
# TARGETARCH 向けバイナリを作る（ビルド段階では QEMU エミュレーション不要）。
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/jp-pii-detect ./cmd/jp-pii-detect

# 実行イメージ。CI のジョブコンテナとしてそのまま使えるよう shell を持つ alpine を
# ベースにし、--staged / --diff スキャンと各 CI の checkout に必要な git を同梱する
# （openssh-client は CircleCI などの SSH ベース checkout 用）。
FROM alpine:3.23
RUN apk add --no-cache ca-certificates git openssh-client
COPY --from=build /out/jp-pii-detect /usr/local/bin/jp-pii-detect
LABEL org.opencontainers.image.title="jp-pii-detect" \
      org.opencontainers.image.description="日本特化の個人情報（PII）静的検出器" \
      org.opencontainers.image.source="https://github.com/baneido/jp-pii-detector" \
      org.opencontainers.image.documentation="https://github.com/baneido/jp-pii-detector/blob/main/docs/integrations.md"
# `docker run --rm -v "$PWD:/scan" <image>` だけでカレントディレクトリを
# フルスキャンできるよう、作業ディレクトリと既定コマンドを設定する。
WORKDIR /scan
ENTRYPOINT ["jp-pii-detect"]
CMD ["scan", "."]
