FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /downorwhy ./cmd/downorwhy
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /downorwhy-action ./cmd/downorwhy-action
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /downorwhy-server ./cmd/downorwhy-server

FROM gcr.io/distroless/static:nonroot
COPY --from=build /downorwhy /downorwhy
COPY --from=build /downorwhy-action /downorwhy-action
COPY --from=build /downorwhy-server /downorwhy-server
ENTRYPOINT ["/downorwhy"]
