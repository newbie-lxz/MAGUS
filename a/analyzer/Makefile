LLVM_CONFIG ?= $(firstword $(wildcard /usr/lib/llvm-*/bin/llvm-config) $(shell command -v llvm-config 2>/dev/null))
PREFIX ?= /usr/local
TARGET ?= llvm-api-analyzer
SRC := llvm_api_analyzer.cpp
CXXFLAGS += -std=c++17 -O2

ifeq ($(origin CXX), default)
CXX := $(firstword $(wildcard /usr/lib/llvm-*/bin/clang++) $(shell command -v clang++ 2>/dev/null) $(shell command -v g++ 2>/dev/null))
endif

.PHONY: all install clean

all: $(TARGET)

$(TARGET): $(SRC)
	@test -n "$(LLVM_CONFIG)" || (echo "llvm-config not found" >&2; exit 1)
	@test -n "$(CXX)" || (echo "clang++ not found" >&2; exit 1)
	$(CXX) $(CXXFLAGS) $(shell $(LLVM_CONFIG) --cxxflags) -o $@ $< $(shell $(LLVM_CONFIG) --ldflags --system-libs --libs core irreader bitreader analysis support)

install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

clean:
	rm -f $(TARGET)
