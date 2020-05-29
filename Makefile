all:
	@echo trying to use GNU make...
	@gmake all || echo please install GNUmake

source-only:
	@gmake source-only

binary-only:
	@gmake binary-only

distrib:
	@gmake distrib

man:
	@gmake man

install:
	@gmake install

document:
	@gmake document

deepclean:
	@gmake deepclean

code-format:
	@gmake code-format

help:
	@gmake help

tests:
	@gmake tests

unit:
	@gmake unit

unit_clean:
	@gmake unit_clean

clean:
	@gmake clean
