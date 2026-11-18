# syntax=docker/dockerfile:1.19@sha256:b6afd42430b15f2d2a4c5a02b919e98a525b785b1aaff16747d2f623364e39b6
# The Cloud runner enclave's two images (deploy/runner/tinfoil-config.yml): the
# broker, running `fount-broker runner`, and fount-supervisor with gVisor; and
# the coordinator enclave's (deploy/coordinator/tinfoil-config.yml). The release
# workflow builds each at each tag; the digests it reports are what the configs
# pin. Release builds: no `dev` tag, so each end of the link takes only an
# attested peer.
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
RUN go build -buildvcs=false -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o /out/fount-broker ./cmd/fount-broker \
 && go build -buildvcs=false -ldflags "-s -w -buildid=" -o /out/fount-supervisor ./cmd/fount-supervisor \
 && go build -buildvcs=false -ldflags "-s -w -buildid=" -o /out/fount-coordinator ./cmd/fount-coordinator \
 && go build -buildvcs=false -tags dev -ldflags "-s -w -buildid= -X main.version=${VERSION}-dev" -o /out/fount-broker-dev ./cmd/fount-broker

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS gvisor
ARG GVISOR=20261109.0
ARG GVISOR_SHA512=1a6b8f74c37b4931ef473f67ec1f601690855bedc52ac709f2fac965c69677aa0426ef44598d8eee1aed72cfdb9df87a2a5f352cb3348880fc61a7732bc10f2a
RUN wget -q -O /gvisor.tar.bz2 "https://storage.googleapis.com/gvisor/releases/release/${GVISOR}/x86_64/gvisor.tar.bz2" \
 && echo "${GVISOR_SHA512}  /gvisor.tar.bz2" | sha512sum -c - \
 && mkdir /out && tar -xjf /gvisor.tar.bz2 -C /out runsc gvisor-bin \
 && /out/runsc --version | head -1

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS broker
COPY --from=build /out/fount-broker /fount-broker
EXPOSE 7400
ENTRYPOINT ["/fount-broker"]

# The broker built with -tags dev, which reads endpoint overrides such as
# FOUNT_BROKER_PROXY (internal/policy/endpoints_dev.go): for a test runner
# whose jobs reach the dev proxy. Test data only.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS broker-dev
COPY --from=build /out/fount-broker-dev /fount-broker
EXPOSE 7400
ENTRYPOINT ["/fount-broker"]

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS supervisor
COPY --from=gvisor /out/ /usr/local/bin/
COPY --from=build /out/fount-supervisor /fount-supervisor
ENTRYPOINT ["/fount-supervisor"]

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS coordinator
COPY --from=build /out/fount-coordinator /fount-coordinator
EXPOSE 8790
ENTRYPOINT ["/fount-coordinator"]
