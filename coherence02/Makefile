CC = g++

#CFLAGS = -static -D DEBUG -g

CFLAGS=

INCLUDES = -luv -lcryptopp -largon2 -lpthread -lntru -lm -loqs -lpistache

LIBS = -L./lib/libuv/.libs/ -L./lib/cryptopp/ -L./lib/argon2/ -L./lib/libntru/ -L./lib/liboqs/.libs/ -L./lib/pistache/prefix/lib/

SRC = -I./lib/libuv/include/ -I./lib/liboqs/include/ -I./lib/rapidjson/include/ -I./lib/pistache/prefix/include/

TARGET = coherence

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) -o ./bin/$(TARGET) $(TARGET).cpp $(SRC) $(INCLUDES) $(LIBS)
