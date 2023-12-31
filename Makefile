GOCMD := go
GOBUILD := $(GOCMD) build -ldflags="-s -w" -trimpath
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I ./ebpf/include

GO_SOURCE := main.go
GO_BINARY := main

EBPF_SOURCE := ebpf/prog.c
EBPF_BINARY := ebpf/prog.elf

all: build_bpf build_go

build_bpf: $(EBPF_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(EBPF_BINARY)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -g -target bpf -c $^  -o $@

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -v -o $@
