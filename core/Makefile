CC = g++

#CFLAGS = -fpermissive -D DEBUG -g

CFLAGS = -fpermissive

INCLUDES = -lcryptopp -largon2 -lpthread -lntru -lm -loqs -lpistache

LIBS = -L./lib/cryptopp/ -L./lib/argon2/ -L./lib/libntru/ -L./lib/liboqs/build/lib/ -L./lib/pistache/prefix/lib/

SRC = -I./lib/liboqs/build/include/ -I./lib/rapidjson/include/ -I./lib/pistache/prefix/include/ -I./lib/liboqs-cpp/include/

TARGET = coherence

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) -o ./bin/$(TARGET) $(TARGET).cpp $(SRC) $(INCLUDES) $(LIBS)
