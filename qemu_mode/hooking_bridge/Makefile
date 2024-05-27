.PHONY: clean

all: plugin
SRC=./src
BLD=./build
INC=-I./inc -I../qemuafl/include -I$(GLIB_H) -I$(GLIB_CONFIG_H)
flags_file=env.txt

$(BLD)/common.o:$(SRC)/common.c $(flags_file)
	gcc $(CFLAGS) -c -fPIC $(INC) -o $(BLD)/common.o $(SRC)/common.c

$(BLD)/patching.o:$(SRC)/patching.c $(flags_file)
	gcc $(CFLAGS) -c -fPIC $(INC) -o $(BLD)/patching.o $(SRC)/patching.c
	
plugin:$(SRC)/main.c $(BLD)/common.o $(BLD)/patching.o $(flags_file)
	gcc $(CFLAGS) -c -fPIC $(INC) -o $(BLD)/plugin.o $(SRC)/main.c
	gcc -shared -o $(BLD)/plugin.so $(BLD)/plugin.o $(BLD)/patching.o $(BLD)/common.o

clean:
	rm -rf $(BLD)/*.o
	rm -rf $(BLD)/*.so