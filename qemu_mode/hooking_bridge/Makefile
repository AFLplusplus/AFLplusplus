.PHONY: clean

all: plugin
SRC=./src
BLD=./build
INC=-I./inc -I../qemuafl/include -I$(GLIB_H) -I$(GLIB_CONFIG_H)

$(BLD)/common.o:$(SRC)/common.c
	gcc $(CFLAGS) -c -fPIC $(INC) -o $(BLD)/common.o $(SRC)/common.c

$(BLD)/patching.o:$(SRC)/patching.c
	gcc $(CFLAGS) -c -fPIC $(INC) -o $(BLD)/patching.o $(SRC)/patching.c
	
plugin:$(SRC)/main.c $(BLD)/common.o $(BLD)/patching.o
	gcc $(CFLAGS) -c -fPIC $(INC) -o $(BLD)/plugin.o $(SRC)/main.c
	gcc -shared -o $(BLD)/plugin.so $(BLD)/plugin.o $(BLD)/patching.o $(BLD)/common.o

clean:
	rm -rf $(BLD)/*.o
	rm -rf $(BLD)/*.so