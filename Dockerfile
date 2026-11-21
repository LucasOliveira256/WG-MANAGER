# syntax=docker/dockerfile:1
# Estágio de compilação: roda na arquitetura do host e faz cross-compile (sem QEMU).
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY . .
# Sem go.sum no projeto, o tidy baixa x/crypto e gera as somas. Com go.sum, esta linha não faz nada.
RUN [ -f go.sum ] || go mod tidy
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w" -o /out/wg-manager . \
 && mkdir -p /out/data

# Imagem final: só o binário, os certificados raiz (para "Verificar TLS") e /data.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/wg-manager /wg-manager
COPY --from=build /out/data /data
ENV PORT=5555 \
    GOMEMLIMIT=24MiB
EXPOSE 5555
VOLUME ["/data"]
ENTRYPOINT ["/wg-manager"]
