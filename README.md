# SC Recorder

Stripchat public-stream recorder with a localhost-only operations dashboard and a
shared 1Fichier upload queue.

## Build and test

```bash
gofmt -w ./cmd ./internal
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o sc ./cmd/sc
```

Run Python checks from the project virtual environment:

```bash
source ~/.venv/bin/activate
python -m py_compile rclone_upload.py
python -m unittest -v test_rclone_upload.py
```

## Runtime

```bash
./sc -config ./config.conf -templates ./templates -keys-dir .
```

The Web server is restricted to the configured localhost address. The default
dashboard is `http://127.0.0.1:18080/sc/`; external TLS and authentication belong
to the reverse proxy.

`SC_PROXY` optionally overrides `[settings] proxy`. HTTP(S) and SOCKS5 URLs are
supported. Leave both values empty for a direct Stripchat connection.

## Upload queue

`do.sh` supervises completed MP4 files in `up/`. It deletes MP4 files smaller
than 5 MiB, then calls `fic_upload_once.sh`, which acquires the host-wide
1Fichier guard and invokes `/root/u/fic_upload.py` with the fixed SC destination
`1f:milo/strip`. Only files confirmed by the official API client are removed.

Systemd units and the Nginx location snippet are in `deploy/`.
