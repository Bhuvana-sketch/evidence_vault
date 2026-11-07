CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Iinclude
LDFLAGS := -lssl -lcrypto -lsqlite3

SRC_DIR := src
BUILD_DIR := build
BIN := vault

SOURCES := $(SRC_DIR)/main.cpp
OBJECTS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SOURCES))

.PHONY: all clean demo

all: $(BIN)

$(BIN): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

demo: demo_test
	./demo_test

demo_test: tests/demo_test.cpp
	$(CXX) $(CXXFLAGS) tests/demo_test.cpp -o demo_test $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(BIN) demo_test data/*.db data/*.json
