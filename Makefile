# Compiler and flags
CC = gcc
CFLAGS = -std=c2x -Wall -Wextra -fPIC -I/usr/include/security -I/opt/homebrew/include
LDFLAGS = -shared -lcurl -ljson-c -lpam -lm

# Directories
SRC_DIR = src
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj

# Target
TARGET = $(BUILD_DIR)/pam_fusionauth_device_grant.so

# Source files
SOURCES = $(SRC_DIR)/config.c \
          $(SRC_DIR)/pam_fusion_auth_device_grant.c


# Object files
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

# Test executable
TEST_TARGET = $(BUILD_DIR)/test
TEST_SOURCES = $(SRC_DIR)/test.c $(SRC_DIR)/config.c

# Default target
.PHONY: all
all: $(TARGET)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Compile object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link the PAM module
$(TARGET): $(OBJECTS) | $(BUILD_DIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Build test executable
.PHONY: test
test: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_SOURCES) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $(TEST_SOURCES) -o $@ -lcurl -ljson-c

# Install the PAM module
.PHONY: install
install: $(TARGET)
	install -m 0644 $(TARGET) /usr/lib/aarch64-linux-gnu/security/
	@echo "PAM module installed to /usr/lib/aarch64-linux-gnu/security/"
# 	@echo "Don't forget to configure /etc/pam_fusionauth.conf"

# Uninstall the PAM module
.PHONY: uninstall
uninstall:
	rm -f /usr/lib/aarch64-linux-gnu/security/pam_fusionauth_device_grant.so
	@echo "PAM module uninstalled"

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

# Rebuild everything
.PHONY: rebuild
rebuild: clean all

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all       - Build the PAM module (default)"
	@echo "  test      - Build the test executable"
	@echo "  install   - Install the PAM module to /lib/security/"
	@echo "  uninstall - Remove the PAM module from /lib/security/"
	@echo "  clean     - Remove build artifacts"
	@echo "  rebuild   - Clean and rebuild"
	@echo "  help      - Show this help message"
