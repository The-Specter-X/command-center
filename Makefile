CC ?= cc
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SYSTEMD_DIR ?= /usr/lib/systemd/system
BUILD_DIR ?= build
CPPFLAGS += -Isrc $(shell $(PKG_CONFIG) --cflags libnftables json-c libsystemd libnl-route-3.0 libcurl)
CFLAGS ?= -O2 -g
CFLAGS += -std=c17 -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wconversion -Wstrict-prototypes -Wmissing-prototypes -Werror -fstack-protector-strong
LDFLAGS += -Wl,-z,relro,-z,now
LDLIBS += $(shell $(PKG_CONFIG) --libs libnftables json-c libsystemd libnl-route-3.0 libcurl)
SOURCES = src/common.c src/config.c src/firewall.c src/transaction.c src/guard.c src/updates.c src/info.c src/status.c src/commands.c src/system.c src/network.c
OBJECTS = $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
.PHONY: all clean check install check-live sanitize analyze check-deps
all: check-deps $(BUILD_DIR)/command-center
check-deps:
	$(PKG_CONFIG) --exists 'libnftables >= 1.0.9' 'json-c >= 0.15' 'libsystemd >= 247' 'libnl-route-3.0 >= 3.2' 'libcurl >= 7.85'
$(BUILD_DIR):
	mkdir -p $@
$(BUILD_DIR)/%.o: src/%.c src/cm.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@
$(BUILD_DIR)/command-center: $(OBJECTS) $(BUILD_DIR)/main.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
$(BUILD_DIR)/test-core: tests/test_core.c $(OBJECTS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@
check: $(BUILD_DIR)/command-center $(BUILD_DIR)/test-core
	./$(BUILD_DIR)/test-core
	python3 tests/test_cli.py ./$(BUILD_DIR)/command-center
check-live: all
	sudo python3 tests/test_live.py ./$(BUILD_DIR)/command-center
sanitize:
	$(MAKE) BUILD_DIR=build/sanitize CFLAGS='-O1 -g -std=c17 -Wall -Wextra -Werror -fno-omit-frame-pointer -fsanitize=address,undefined' LDFLAGS='-fsanitize=address,undefined' check
analyze:
	$(MAKE) BUILD_DIR=build/analyze CFLAGS='-O0 -g -std=c17 -Wall -Wextra -Werror -fanalyzer' all
install: all
	install -Dm755 $(BUILD_DIR)/command-center $(DESTDIR)$(BINDIR)/command-center
	install -Dm644 packaging/command-center.1 $(DESTDIR)$(PREFIX)/share/man/man1/command-center.1
	install -Dm644 packaging/systemd/command-center.service $(DESTDIR)$(SYSTEMD_DIR)/command-center.service
	install -Dm644 packaging/systemd/command-center-guard.service $(DESTDIR)$(SYSTEMD_DIR)/command-center-guard.service
	install -d $(DESTDIR)$(PREFIX)/share/doc/command-center
	install -m644 README.md PROJECT_OVERVIEW.md SECURITY.md $(DESTDIR)$(PREFIX)/share/doc/command-center/
	install -d $(DESTDIR)$(PREFIX)/share/doc/command-center/docs
	install -m644 docs/*.md $(DESTDIR)$(PREFIX)/share/doc/command-center/docs/
clean:
	rm -rf build
-include $(OBJECTS:.o=.d) $(BUILD_DIR)/main.d
