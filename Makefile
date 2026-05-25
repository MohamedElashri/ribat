GO ?= go
PREFIX ?= /usr/local
SYSCONFDIR ?= /etc
LOCALSTATEDIR ?= /var/lib
LOGDIR ?= /var/log
SYSTEMD_UNIT_DIR ?= /etc/systemd/system
DOCKER_SYSTEMD_DROPIN_DIR ?= /etc/systemd/system/docker.service.d
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
SOURCE_DATE_EPOCH ?=
DATE ?= $(shell if [ -n "$(SOURCE_DATE_EPOCH)" ]; then date -u -d "@$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ; else date -u +%Y-%m-%dT%H:%M:%SZ; fi)

BINARY := bin/ribat
CONFIG_PATH := $(SYSCONFDIR)/ribat/config.yaml
STATE_DIR := $(LOCALSTATEDIR)/ribat
AUDIT_DIR := $(LOGDIR)/ribat
LDFLAGS := -s -w -buildid= -X github.com/MohamedElashri/ribat/internal/version.Version=$(VERSION) -X github.com/MohamedElashri/ribat/internal/version.Commit=$(COMMIT) -X github.com/MohamedElashri/ribat/internal/version.Date=$(DATE)
RELEASE_TARGETS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
DOCS_GO_ENV ?= GOCACHE=$(CURDIR)/.gocache

.PHONY: build test test-integration test-docker-live test-host-authz-live docs-build docs-serve release-snapshot install install-docker-dropin uninstall clean

build:
	$(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ribat

test:
	$(GO) test ./...

test-integration:
	RIBAT_INTEGRATION_TESTS=1 $(GO) test ./tests/integration

test-docker-live: build
	RIBAT_DOCKER_LIVE_TESTS=1 RIBAT_BIN=./$(BINARY) scripts/live-docker-validation.sh

test-host-authz-live:
	RIBAT_HOST_LIVE_TESTS=1 scripts/live-host-authz-validation.sh

docs-build:
	@if [ -d ../nida ]; then \
		cd ../nida && $(DOCS_GO_ENV) $(GO) run ./cmd/nida build --site $(CURDIR)/docs; \
	else \
		$(DOCS_GO_ENV) $(GO) run github.com/MohamedElashri/nida/cmd/nida@main build --site ./docs; \
	fi

docs-serve:
	@if [ -d ../nida ]; then \
		cd ../nida && $(DOCS_GO_ENV) $(GO) run ./cmd/nida serve --site $(CURDIR)/docs; \
	else \
		$(DOCS_GO_ENV) $(GO) run github.com/MohamedElashri/nida/cmd/nida@main serve --site ./docs; \
	fi

release-snapshot:
	rm -rf dist
	mkdir -p dist
	@for target in $(RELEASE_TARGETS); do \
		os=$${target%/*}; \
		arch=$${target#*/}; \
		binary=ribat; \
		if [ "$$os" = "windows" ]; then binary=ribat.exe; fi; \
		package="ribat_$(VERSION)_$${os}_$${arch}"; \
		workdir="dist/$${package}"; \
		mkdir -p "$$workdir"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o "$$workdir/$$binary" ./cmd/ribat; \
		if [ -n "$(SOURCE_DATE_EPOCH)" ]; then \
			tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$(SOURCE_DATE_EPOCH)" -czf "dist/$${package}.tar.gz" -C "$$workdir" "$$binary"; \
		else \
			tar --sort=name --owner=0 --group=0 --numeric-owner -czf "dist/$${package}.tar.gz" -C "$$workdir" "$$binary"; \
		fi; \
		rm -rf "$$workdir"; \
	done
	cd dist && sha256sum *.tar.gz > checksums.txt

install: build
	install -d -m 0755 $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/ribat
	install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/ribat
	@if [ ! -f "$(DESTDIR)$(CONFIG_PATH)" ]; then \
		install -m 0644 configs/ribat.example.yaml "$(DESTDIR)$(CONFIG_PATH)"; \
	else \
		echo "keeping existing $(DESTDIR)$(CONFIG_PATH)"; \
	fi
	install -d -m 0750 $(DESTDIR)$(STATE_DIR)
	install -d -m 0750 $(DESTDIR)$(AUDIT_DIR)
	install -d -m 0755 $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	install -m 0644 packaging/systemd/ribat.service $(DESTDIR)$(SYSTEMD_UNIT_DIR)/ribat.service

install-docker-dropin:
	install -d -m 0755 $(DESTDIR)$(DOCKER_SYSTEMD_DROPIN_DIR)
	install -m 0644 packaging/systemd/docker-ribat.conf $(DESTDIR)$(DOCKER_SYSTEMD_DROPIN_DIR)/10-ribat.conf

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/ribat
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/ribat.service
	rm -f $(DESTDIR)$(DOCKER_SYSTEMD_DROPIN_DIR)/10-ribat.conf
	@echo "left $(DESTDIR)$(SYSCONFDIR)/ribat, $(DESTDIR)$(STATE_DIR), and $(DESTDIR)$(AUDIT_DIR) in place"

clean:
	rm -rf bin dist
