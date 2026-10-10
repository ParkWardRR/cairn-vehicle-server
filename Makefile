# Cairn server builds.
#
# The point of this file is the instruction-set baseline. Go defaults to
# GOAMD64=v1, which is plain SSE2 from 2003, and raising it is the only
# compile-time knob that changes code generation on amd64.
#
# What it does and does not buy, measured on the deploy host (i7-13700T, Go
# 1.27, five runs each, single-threaded, MB/s):
#
#                                   v1       v3     delta
#   ScanSegment (4096 frames)    817.4    945.7    +15.7%
#   CRC-32 (1 MiB)             32194.0  31913.2     -0.9%
#   SHA-256 (1 MiB)             2038.5   2053.1     +0.7%
#   Merkle (1024 leaves)         238.0    236.4     -0.7%
#
# Only the segment scan moves, and that is the one that matters for ingest
# throughput — it is ordinary Go doing frame parsing and bounds checks, so
# better codegen shows up directly.
#
# The primitives do not move because they were never compiled Go in the first
# place: hash/crc32 dispatches to a carry-less multiply routine (PCLMULQDQ) and
# crypto/sha256 to SHA-NI, both hand-written assembly selected at run time from
# CPU feature bits. GOAMD64 cannot improve hand-written assembly, and 32 GB/s
# CRC and 2 GB/s SHA-256 confirm those paths are already active — a table-driven
# CRC-32 runs nearer 1 GB/s and a software SHA-256 nearer 0.3 GB/s. Ed25519 has
# no SIMD path in the standard library and sits off the hot path at one
# verification per receipt.
#
# v4 is deliberately not used: it requires AVX-512, which this CPU does not
# expose — 13th generation Intel parts have it fused off.
#
# The guard matters. A v3 binary executing on a CPU without AVX2, BMI2 and FMA
# dies with SIGILL at startup, not with a diagnosable error, so `make build`
# checks the host's feature bits and falls back to v1 with a warning rather than
# producing an executable that cannot run where it was built.

GO      ?= go
BINDIR  ?= bin

# The build identity reported by /healthz (internal/buildinfo). Without a git checkout
# the binary still reports whatever the Go toolchain stamped into it.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
# Which release channel this build belongs to: dev, beta or stable. dev is the honest default
# for a build made by hand; deploy/deploy-v3.sh --channel passes the other two. An unrecognised
# value reads as dev and never as stable. See the front door's docs/release-process.md.
CHANNEL ?= dev
BUILDINFO := -X github.com/ParkWardRR/cairn-vehicle-server/internal/buildinfo.Version=$(VERSION) -X github.com/ParkWardRR/cairn-vehicle-server/internal/buildinfo.Commit=$(COMMIT) -X github.com/ParkWardRR/cairn-vehicle-server/internal/buildinfo.Channel=$(CHANNEL)
LDFLAGS ?= -s -w $(BUILDINFO)

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Resolve the baseline for this host, unless the caller pinned one.
ifeq ($(origin GOAMD64), undefined)
ifeq ($(UNAME_M),x86_64)
CPUFLAGS   := $(shell grep -m1 ^flags /proc/cpuinfo 2>/dev/null)
HAS_V3     := $(if $(and $(findstring avx2,$(CPUFLAGS)),$(findstring bmi2,$(CPUFLAGS)),$(findstring fma,$(CPUFLAGS))),yes,no)
GOAMD64    := $(if $(filter yes,$(HAS_V3)),v3,v1)
endif
endif

# Empty on non-amd64 hosts: passing GOAMD64= to the toolchain is an error, and
# the variable is meaningless on arm64 anyway.
ENV := $(if $(GOAMD64),GOAMD64=$(GOAMD64),)

CMDS := cairn-server cairn-admin cairn-verify cairn-ledger cairn-signfw

.PHONY: all build build-tsdb test vet bench bench-isa clean cpuinfo

all: build

cpuinfo:
	@echo "arch        : $(UNAME_M) ($(UNAME_S))"
	@echo "GOAMD64     : $(if $(GOAMD64),$(GOAMD64),n/a on this arch)"
ifeq ($(UNAME_M),x86_64)
	@test "$(GOAMD64)" = v3 || echo "NOTE: avx2/bmi2/fma not all present; staying on v1"
endif

build: cpuinfo
	@mkdir -p $(BINDIR)
	@for c in $(CMDS); do \
	  echo "building $$c"; \
	  $(ENV) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/$$c ./cmd/$$c || exit 1; \
	done
	@echo "built into $(BINDIR)/$(if $(GOAMD64), with GOAMD64=$(GOAMD64),)"

# cairn-tsdb links DuckDB statically through cgo, so it needs a C toolchain and
# is kept out of CMDS: the ingest binaries stay pure Go and cross-compilable.
build-tsdb: cpuinfo
	@mkdir -p $(BINDIR)
	CGO_ENABLED=1 $(ENV) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/cairn-tsdb ./cmd/cairn-tsdb

test:
	$(ENV) $(GO) test ./...

vet:
	$(ENV) $(GO) vet ./...

bench:
	$(ENV) $(GO) test ./format -run '^$$' -bench Hardware -benchtime 300ms -count 5 -cpu 1

# Re-measure the table at the top of this file. Five runs each so the comparison
# carries a standard deviation rather than one sample.
bench-isa:
	@for lvl in v1 v3; do \
	  echo "=== GOAMD64=$$lvl ==="; \
	  GOAMD64=$$lvl $(GO) test ./format -run '^$$' -bench Hardware \
	    -benchtime 300ms -count 5 -cpu 1 | grep -E '^Benchmark|MB/s'; \
	done

clean:
	rm -rf $(BINDIR)
