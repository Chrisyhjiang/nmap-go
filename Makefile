CXX = g++
CXXFLAGS = -std=c++11 -Wall -Iinclude -I/opt/homebrew/Cellar/libtins/4.5/include
LDFLAGS = -lpthread -L/opt/homebrew/Cellar/libtins/4.5/lib -ltins

TARGET = bin/my_nmap
SRCS = src/main.cpp src/scanner.cpp src/output.cpp src/syn_scanner.cpp
HEADERS = include/scanner.h include/output.h include/syn_scanner.h

OBJS = $(patsubst src/%.cpp, bin/%.o, $(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CXX) -o $(TARGET) $(OBJS) $(LDFLAGS)

bin/%.o: src/%.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f bin/*.o $(TARGET)
