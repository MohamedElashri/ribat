GO ?= go
PREFIX ?= /usr/local
SYSCONFDIR ?= /etc
LOCALSTATEDIR ?= /var/lib
LOGDIR ?= /var/log
SYSTEMD_UNIT_DIR ?= /etc/systemd/system
DOCKER_SYSTEMD_DROPIN_DIR ?= /etc/systemd/system/docker.service.d

BINARY := bin/ribat
CONFIG_PATH := $(SYSCONFDIR)/ribat/config.yaml
STATE_DIR := $(LOCALSTATEDIR)/ribat
AUDIT_DIR := $(LOGDIR)/ribat

.PHONY: build test install install-docker-dropin uninstall clean

build:
	$(GO) build -o $(BINARY) ./cmd/ribat

test:
	$(GO) test ./...

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
	rm -rf bin
