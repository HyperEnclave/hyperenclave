# Commands:
#   make build                  Build
#   make test                   Run `cargo test`
#   make format                 Format the code
#   make format-check           Check whether codes needs format
#   make clippy                 Run `cargo clippy`
#   make disasm                 Open the disassemble file of the last build
#   make clean                  Clean
#
# Arguments:
#   LOG  = off | error | warn | info | debug | trace
#   ARCH = x86_64
#   VENDOR = intel | amd        [ x86_64 only ] Build for Intel or AMD CPUs.
#   STATS = on | off            Given performance statistics when run enclaves.
#   SME = on | off              [ amd only] Enable AMD Secure Memory Encryption.
#   INTR = on | off             Enable interrupts during enclaves running.

ECHO := /bin/echo -e
CYAN := \033[1;36m
GREEN := \033[1;32m
RED := \033[1;31m
NO_COLOR := \033[0m

define format-rust
	output=$$(cargo fmt -- --check 2>&1); retval=$$?; \
		if [ $$retval -eq 1 ]; then \
			$(ECHO) "$$output"; \
			cargo fmt; \
			$(ECHO) "$(GREEN)\nRust code format corrected.$(NO_COLOR)"; \
		fi
endef

define format-check-rust
	output=$$(cargo fmt -- --check 2>&1); retval=$$?; \
		if [ $$retval -eq 1 ]; then \
			$(ECHO) "$(RED)\nSome format issues of Rust code are detected:$(NO_COLOR)"; \
			$(ECHO) "\n$$output"; \
			$(ECHO) "\nTo get rid of the format warnings above, run $(CYAN)"make format"$(NO_COLOR) to correct"; \
		fi
endef

ARCH ?= x86_64
VENDOR ?= amd
LOG ?=
STATS ?= off
SME ?= on
INTR ?= on

# do not support debug mode
MODE := release

export MODE
export LOG
export ARCH
export VENDOR
export STATS
export SME
export INTR

OBJDUMP ?= objdump
OBJCOPY ?= objcopy

elf_name     := rust-hypervisor
build_path   := target/$(ARCH)/$(MODE)
target_elf   := $(build_path)/$(elf_name)
target_bin   := $(build_path)/$(elf_name).bin
install_path := /lib/firmware/$(elf_name)-$(VENDOR)

rust_flags="-C code-model=medium"

ifeq ($(ARCH), x86_64)
  features := $(VENDOR)
else
  features :=
endif

ifeq ($(STATS), on)
  features += stats
endif

ifeq ($(SME), on)
  ifneq ($(VENDOR), amd)
    $(error `SME=on` is only available when `VENDOR=amd`)
  endif
  features += sme
endif

ifeq ($(INTR), on)
  features += enclave_interrupt
endif

build_args := --features "$(features)" --target $(ARCH).json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem
ifeq ($(MODE), release)
  build_args += --release
endif

.PHONY: all
all: githooks elf

.PHONY: githooks
githooks:
	@find .git/hooks -type l -exec rm {} \; && find .githooks -type f -exec ln -sf ../../{} .git/hooks/ \;


.PHONY: elf
elf:
	RUSTFLAGS=$(rust_flags) cargo build $(build_args)

$(target_bin): elf
	$(OBJCOPY) $(target_elf) --strip-all -O binary $@

.PHONY: disasm
disasm:
	$(OBJDUMP) -d $(target_elf) -M intel | less

.PHONY: clippy
clippy:
	cargo clippy $(build_args)

.PHONY: test
test:
	cargo test --features "$(features)"

.PHONY: format-check
format-check:
	@$(call format-check-rust)

.PHONY: format
format:
	@$(call format-rust)

.PHONY: clean
clean:
	cargo clean
	$(MAKE) clean -C ../libtpm

.PHONY: install
install:
	sudo cp $(target_elf) $(install_path)

.PHONY: scp
scp:
	scp -P 3399 -r $(target_elf) root@localhost:$(install_path)

.PHONY: ssh
ssh:
	ssh -p 3399 root@localhost
