CC = g++
CFLAGS  = -g -std=c++17 -Werror
TARGET  = mytftpclient

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) $(TARGET).cpp -o $(TARGET)

debug: 
	$(CC) $(CFLAGS) -DDEBUG $(TARGET).cpp -o debug

clean:
	$(RM) $(TARGET) debug