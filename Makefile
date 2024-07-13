CXX = g++
CXXFLAGS = -std=c++11 -Wall -Iinclude

SRC_DIR = src
PACKETS_DIR = src/packets
OBJ_DIR = bin
BIN_DIR = bin
SRC_FILES = $(wildcard $(SRC_DIR)/*.cpp) $(wildcard $(PACKETS_DIR)/*.cpp)
OBJ_FILES = $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(notdir $(SRC_FILES)))
TARGET = $(BIN_DIR)/my_nmap

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJ_FILES)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(PACKETS_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_DIR)/*.o $(TARGET)
