# syntax=docker/dockerfile:1
#
# Certower server image. Build: docker build -t certower .
# Data (database and key-encryption key) lives in the /data volume.

FROM --platform=$BUILDPLATFORM node:26-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist web/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/tntrock/certower/internal/version.Version=$VERSION -X github.com/tntrock/certower/internal/version.Commit=$COMMIT" \
      -o /out/certower ./cmd/certower \
 && mkdir -p /out/data

# Distroless: no shell or package manager, runs as an unprivileged user,
# includes CA certificates and time zone data.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/certower /usr/local/bin/certower
COPY --from=build --chown=65532:65532 /out/data /data
WORKDIR /data
ENV CERTOWER_DB=sqlite:/data/certower.db \
    CERTOWER_KEK_FILE=/data/certower.kek \
    CERTOWER_LISTEN=:8080 \
    CERTOWER_AGENT_LISTEN=:8443
VOLUME /data
EXPOSE 8080 8443
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["certower", "healthcheck"]
ENTRYPOINT ["certower"]
CMD ["serve"]
