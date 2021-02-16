all: fuzz

../target:
	$(MAKE) -C ..

fuzz: ../target
	rm -rf ./ouptput
	../../../../afl-fuzz -s 1 -U -i ../sample_inputs -o ./output -- python3 harness.py @@
