#!/usr/bin/env python

from XmlMutatorMin import XmlMutatorMin

# Default settings (production mode)

__mutator__ = None
__seed__ = "RANDOM"
__log__ = False
__log_file__ = "wrapper.log"


# AFL functions
def log(text):
    """
    Logger
    """

    global __seed__
    global __log__
    global __log_file__

    if __log__:
        with open(__log_file__, "a") as logf:
            logf.write("[%s] %s\n" % (__seed__, text))


def init(seed):
    """
    Called once when AFL starts up. Seed is used to identify the AFL instance in log files
    """

    global __mutator__
    global __seed__

    # Get the seed
    __seed__ = seed

    # Create a global mutation class
    try:
        __mutator__ = XmlMutatorMin(__seed__, verbose=__log__)
        log("init(): Mutator created")
    except RuntimeError as e:
        log("init(): Can't create mutator: %s" % e.message)


def fuzz(buf, add_buf, max_size):
    """
    Called for each fuzzing iteration.
    """

    global __mutator__

    # Do we have a working mutator object?
    if __mutator__ is None:
        log("fuzz(): Can't fuzz, no mutator available")
        return buf

    # Try to use the AFL buffer
    via_buffer = True

    # Interpret the AFL buffer (an array of bytes) as a string
    if via_buffer:
        try:
            buf_str = str(buf)
            log("fuzz(): AFL buffer converted to a string")
        except Exception:
            via_buffer = False
            log("fuzz(): Can't convert AFL buffer to a string")

    # Load XML from the AFL string
    if via_buffer:
        try:
            __mutator__.init_from_string(buf_str)
            log(
                "fuzz(): Mutator successfully initialized with AFL buffer (%d bytes)"
                % len(buf_str)
            )
        except Exception:
            via_buffer = False
            log("fuzz(): Can't initialize mutator with AFL buffer")

    # If init from AFL buffer wasn't succesful
    if not via_buffer:
        log("fuzz(): Returning unmodified AFL buffer")
        return buf

    # Sucessful initialization -> mutate
    try:
        __mutator__.mutate(max=5)
        log("fuzz(): Input mutated")
    except Exception:
        log("fuzz(): Can't mutate input => returning buf")
        return buf

    # Convert mutated data to a array of bytes
    try:
        data = bytearray(__mutator__.save_to_string())
        log("fuzz(): Mutated data converted as bytes")
    except Exception:
        log("fuzz(): Can't convert mutated data to bytes => returning buf")
        return buf

    # Everything went fine, returning mutated content
    log("fuzz(): Returning %d bytes" % len(data))
    return data


# Main (for debug)
if __name__ == "__main__":

    __log__ = True
    __log_file__ = "/dev/stdout"
    __seed__ = "RANDOM"

    init(__seed__)

    in_1 = bytearray(
        "<foo ddd='eeee'>ffff<a b='c' d='456' eee='ffffff'>zzzzzzzzzzzz</a><b yyy='YYY' zzz='ZZZ'></b></foo>"
    )
    in_2 = bytearray("<abc abc123='456' abcCBA='ppppppppppppppppppppppppppppp'/>")
    out = fuzz(in_1, in_2)
    print(out)
