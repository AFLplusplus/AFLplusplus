CFLAGS=`pkg-config --cflags gtk+-3.0`
LDFLAGS=`pkg-config --libs gtk+-3.0`

all:  afl-plot-ui

afl-plot-ui:	afl-plot-ui.c
	$(CC) $(CFLAGS) -o afl-plot-ui afl-plot-ui.c $(LDFLAGS)

clean:
	rm -f afl-plot-ui
