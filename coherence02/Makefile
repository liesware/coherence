CC = g++

#CFLAGS = -D DEBUG -g -Werror

CFALAGS= -Werror

INCLUDES = -Ilibuv/ -Icryptopp/ -Iargon2/

LIBS = ./lib/libuv/.libs/libuv.so ./lib/cryptopp/libcryptopp.so ./lib/argon2/libargon2.so.1

TARGET = coherence

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) -o $(TARGET) $(TARGET).c


