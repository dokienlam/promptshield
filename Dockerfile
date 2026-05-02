FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/promptshield .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/promptshield /promptshield
EXPOSE 8080 8081
USER nonroot
ENTRYPOINT ["/promptshield"]
CMD ["--listen", ":8080", "--dashboard", ":8081", "--db", "/data/promptshield.db"]
