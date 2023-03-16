ARG GO_VERSION=1.16
FROM registry.access.redhat.com/ubi8/go-toolset:latest AS builder
WORKDIR /sandbox/

USER root
RUN chown -R ${USER_UID}:0 /sandbox
USER ${USER_UID}

COPY ./ ./
ENV GOOS=linux
ENV CGO_ENABLED=0
RUN go build ./cmd/sandbox-metrics
RUN go build ./cmd/sandbox-list

FROM registry.access.redhat.com/ubi8/ubi-minimal:latest AS deploy
RUN microdnf install -y rsync tar
WORKDIR /sandbox/
USER ${USER_UID}
COPY build/github_known_hosts /ssh/known_hosts
env SSH_KNOWN_HOSTS /ssh/known_hosts
COPY --from=builder /sandbox/sandbox-metrics ./
CMD ["./sandbox-metrics"]
