CC = g++

#CFLAGS = -static -D DEBUG -g

CFLAGS= -Werror -static

INCLUDES = -luv -lcryptopp -largon2 -lpthread -lntru -lm -loqs

LIBS = -L./lib/libuv/.libs/ -L./lib/cryptopp/ -L./lib/argon2/ -L./lib/libntru/ -L./lib/liboqs/.libs/

SRC = -I./lib/libuv/include/ -I./lib/liboqs/include/ -I./lib/rapidjson/include/

TARGET = coherence

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o ./bin/$(TARGET) $(TARGET).c $(SRC) $(INCLUDES) $(LIBS)
