CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Werror -std=c11 -g -O2
CFLAGS  += -I include

SRC_DIR   = src
TEST_DIR  = tests
BUILD_DIR = build

# Source files
SRCS = $(SRC_DIR)/buf.c \
       $(SRC_DIR)/caps.c \
       $(SRC_DIR)/protocol.c \
       $(SRC_DIR)/compound.c

OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Library
LIB = $(BUILD_DIR)/lib9pN.a

# Test binary
TEST_SRC  = $(TEST_DIR)/test_9pN.c
TEST_BIN  = $(BUILD_DIR)/test_9pN

.PHONY: all clean test

all: $(LIB)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c include/9pN.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	ar rcs $@ $^

$(TEST_BIN): $(TEST_SRC) $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -l9pN -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
