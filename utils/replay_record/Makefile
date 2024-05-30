all:
	test `grep '//[\s\t ]*#define[\s\t ]*AFL_PERSISTENT_RECORD' ../../include/config.h | wc -l` -eq 0 || (echo "AFL_PERSISTENT_RECORD must be enabled in config.h"; exit 1)
	../../afl-clang-fast -o persistent_demo_replay persistent_demo_replay.c
	${CC} -I ../../include -o persistent_demo_replay_compat persistent_demo_replay.c
	${CC} -g -I ../../include -DAFL_PERSISTENT_REPLAY_ARGPARSE -o persistent_demo_replay_argparse persistent_demo_replay.c

clean:
	rm -f persistent_demo_replay persistent_demo_replay_argparse persistent_demo_replay_compat
