FROM golang:1.21-alpine AS builder

WORKDIR /app

# 安装依赖
RUN apk add --no-cache git ca-certificates tzdata

# 复制 go mod 文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -o kong-cert-sync ./cmd/controller

# 创建最终镜像
FROM alpine:3.18

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# 复制可执行文件
COPY --from=builder /app/kong-cert-sync .
# 复制配置文件
COPY config/config.yaml ./config/

# 设置时区
ENV TZ=Asia/Shanghai

ENTRYPOINT ["./kong-cert-sync", "--config=/app/config/config.yaml"]