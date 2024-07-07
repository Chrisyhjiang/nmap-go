CXX = g++
CXXFLAGS = -std=c++11 -Wall -Iinclude
LDFLAGS = -lpthread

TARGET = bin/my_nmap
SRCS = src/main.cpp src/scanner.cpp src/output.cpp
HEADERS = include/scanner.h include/output.h

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
