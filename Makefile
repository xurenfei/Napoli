SOURCE_FILES?=./...
TEST_PATTERN?=.
TEST_OPTIONS?=

# 产物放在仓库上一级，与 src 平级，不混进源码树。
# 用 abspath 而不是写死绝对路径，换机器或换目录时不用再改。
DIST_DIR ?= $(abspath $(CURDIR)/../dist)
BIN_SERVER ?= napolis
BIN_CLIENT ?= napolic

export PATH := ./bin:$(PATH)

# 参与 vet / 测试 / 漏洞扫描的包集合。排除 gui 与 cmd/npc 两个原因：
#   gui      依赖 fyne/glfw，必须开 cgo，且与本次服务端改动无关；
#   cmd/npc  npc.go 与 sdk.go 同属 package main 且各有一个 main，
#            是 c-shared 构建的产物，只有按单文件构建才成立。
SCAN_PKGS ?= ./lib/... ./client/... ./server/... ./bridge/... ./web/... ./cmd/nps/...

# -coverpkg 要求逗号分隔，而包列表是空格分隔的，直接拼接会被 shell 拆成多个参数。
comma := ,
empty :=
space := $(empty) $(empty)
SCAN_PKGS_COMMA := $(subst $(space),$(comma),$(strip $(SCAN_PKGS)))

# 只作用于 build 目标。不做全局 export：gui 目录依赖 fyne/glfw，
# 那部分必须开 cgo，全局关掉会让 govulncheck、vet 之类整包扫描直接编译失败。
BUILD_CGO ?= 0

# -trimpath drops local filesystem paths from the binary,
# -s -w strips the symbol table and DWARF data.
BUILD_LDFLAGS ?= -trimpath -ldflags "-s -w"

# Build both server and client into $(DIST_DIR)
# 刻意不写成基于文件时间戳的规则：源文件分散在多个包，
# 靠 $(DIST_DIR)/x: y.go 声明依赖很容易漏掉，导致改了代码不重编。
build:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=$(BUILD_CGO) go build $(BUILD_LDFLAGS) -o $(DIST_DIR)/$(BIN_SERVER) ./cmd/nps/nps.go
	CGO_ENABLED=$(BUILD_CGO) go build $(BUILD_LDFLAGS) -o $(DIST_DIR)/$(BIN_CLIENT) ./cmd/npc/npc.go
.PHONY: build

# Install all the build and lint dependencies
setup:
	go mod download
.PHONY: setup

# Run all the tests
test:
	go test $(TEST_OPTIONS) -failfast -race -coverpkg=$(SCAN_PKGS_COMMA) -covermode=atomic -coverprofile=coverage.txt $(SCAN_PKGS) -run $(TEST_PATTERN) -timeout=2m
.PHONY: test

# Run all the tests and opens the coverage report
cover: test
	go tool cover -html=coverage.txt
.PHONY: cover

# gofmt and goimports all go files
fmt:
	find . -name '*.go' -not -wholename './vendor/*' | while read -r file; do gofmt -w -s "$$file"; goimports -w "$$file"; done
.PHONY: fmt

# Run all the linters
# copylocks 单独关掉：项目里 sync.Map / Flow 按值传递十余处（GetMapKeys、
# storeSyncMapToFile、NewTunnel 等），是既有技术债，修它要改跨包签名并回归核心数据路径。
# 不在本轮范围，但不当成阻断项，完整结果用 lint-strict 看。
lint:
	go vet -copylocks=false $(SCAN_PKGS)
.PHONY: lint

lint-strict:
	go vet $(SCAN_PKGS)
.PHONY: lint-strict

# Report known vulnerabilities in the module graph
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest $(SCAN_PKGS)
.PHONY: vuln

# Clean go.mod
go-mod-tidy:
	@go mod tidy -v
	@git diff HEAD
	@git diff-index --quiet HEAD
.PHONY: go-mod-tidy

# Run all the tests and code checks
ci: build test lint go-mod-tidy
.PHONY: ci

# Generate the static documentation
static:
	@hugo --enableGitInfo --source www
.PHONY: static

# Show to-do items per file.
todo:
	@grep \
		--exclude-dir=vendor \
		--exclude-dir=node_modules \
		--exclude=Makefile \
		--text \
		--color \
		-nRo -E ' TODO:.*|SkipNow' .
.PHONY: todo

clean:
	rm -rf $(DIST_DIR) coverage.txt
.PHONY: clean

.DEFAULT_GOAL := build
