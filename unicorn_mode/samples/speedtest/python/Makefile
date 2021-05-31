.PHONY: all fuzz

all: ../target

afl-fuzz: ../../../../afl-fuzz
../../../../afl-fuzz:
	$(MAKE) -C ../../../../ afl-fuzz


../target:
	$(MAKE) -C ..

fuzz: all afl-fuzz
	rm -rf ./ouptput
	../../../../afl-fuzz -s 1 -U -i ../sample_inputs -o ./output -- python3 harness.py @@
