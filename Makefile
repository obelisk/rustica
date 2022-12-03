debug ?=

$(info debug is $(debug))

ifdef debug
  release :=
  target :=debug
  extension :=debug
else
  release :=--release
  target :=release
  extension :=
endif

all:
	cargo build $(release) --features=all

build: all

cli:
	cargo build $(release) --features=all --bin=rustica-agent-cli

gui:
	cargo build $(release) --features=all --bin=rustica-agent-gui

server:
	cargo build $(release) --features=all --bin=rustica

server-no-yk:
	cargo build $(release) --features="amazon-kms,influx,splunk,local-db,webhook" --bin=rustica


help:
	@echo "usage: make <cli/gui/server/server-no-yk> [debug=1]"
