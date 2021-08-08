# afl-plot-ui

`afl-plot-ui` is a helper utility for rendering the GNUplot graphs in a GTK window. This allows to real time resizing, scrolling, and cursor positioning features while viewing the graph. This utility also provides options to hide graphs using check buttons.

Currently, this utility is not built by default.
You can manually build and install `afl-plot-ui` as follows

```shell
sudo apt install libgtk-3-0 libgtk-3-dev pkg-config
make
cd ../../
sudo make install
```

*NOTE:* This utility is not meant to be used standalone. Never run this utility directly. Always run [`afl-plot`](../../afl-plot), which will, in turn, invoke this utility (when run using `-g` or `--graphical` flag).