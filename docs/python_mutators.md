# Adding custom mutators to AFL using Python modules

  This file describes how you can utilize the external Python API to write
  your own custom mutation routines.

  Note: This feature is highly experimental. Use at your own risk.

  Implemented by Christian Holler (:decoder) <choller@mozilla.com>.

  NOTE: Only cPython 2.7, 3.7 and above are supported, although others may work.
  Depending on with which version afl-fuzz was compiled against, you must use
  python2 or python3 syntax in your scripts!
  After a major version upgrade (e.g. 3.7 -> 3.8), a recompilation of afl-fuzz may be needed.

  For an example and a template see ../examples/python_mutators/


## 1) Description and purpose

While AFLFuzz comes with a good selection of generic deterministic and
non-deterministic mutation operations, it sometimes might make sense to extend
these to implement strategies more specific to the target you are fuzzing.

For simplicity and in order to allow people without C knowledge to extend
AFLFuzz, I implemented a "Python" stage that can make use of an external
module (written in Python) that implements a custom mutation stage.

The main motivation behind this is to lower the barrier for people
experimenting with this tool. Hopefully, someone will be able to do useful
things with this extension.

If you find it useful, have questions or need additional features added to the
interface, feel free to send a mail to <choller@mozilla.com>.

See the following information to get a better pictures:
  https://www.agarri.fr/docs/XML_Fuzzing-NullCon2017-PUBLIC.pdf
  https://bugs.chromium.org/p/chromium/issues/detail?id=930663


## 2) How the Python module looks like

You can find a simple example in pymodules/example.py including documentation
explaining each function. In the same directory, you can find another simple
module that performs simple mutations.

Right now, "init" is called at program startup and can be used to perform any
kinds of one-time initializations while "fuzz" is called each time a mutation
is requested.

There is also optional support for a trimming API, see the section below for
further information about this feature.


## 3) How to compile AFLFuzz with Python support

You must install the python 3 or 2 development package of your Linux
distribution before this will work. On Debian/Ubuntu/Kali this can be done
with either:
  apt install python3-dev
or
  apt install python-dev
Note that for some distributions you might also need the package python[23]-apt

A prerequisite for using this mode is to compile AFLFuzz with Python support.

The AFL++ Makefile detects Python 3 and 2 through `python-config` if is is in the PATH
and compiles afl-fuzz with the feature if available.

In case your setup is different set the necessary variables like this:
PYTHON_INCLUDE=/path/to/python/include LDFLAGS=-L/path/to/python/lib make


## 4) How to run AFLFuzz with your custom module

You must pass the module name inside the env variable AFL_PYTHON_MODULE.

In addition, if you are trying to load the module from the local directory,
you must adjust your PYTHONPATH to reflect this circumstance. The following
command should work if you are inside the aflfuzz directory:

$ AFL_PYTHON_MODULE="pymodules.test" PYTHONPATH=. ./afl-fuzz

Optionally, the following environment variables are supported:

AFL_PYTHON_ONLY - Disable all other mutation stages. This can prevent broken
                  testcases (those that your Python module can't work with
                  anymore) to fill up your queue. Best combined with a custom
                  trimming routine (see below) because trimming can cause the
                  same test breakage like havoc and splice.

AFL_DEBUG       - When combined with AFL_NO_UI, this causes the C trimming code
                  to emit additional messages about the performance and actions
                  of your custom Python trimmer. Use this to see if it works :)


## 5) Order and statistics

The Python stage is set to be the first non-deterministic stage (right before
the havoc stage). In the statistics however, it shows up as the third number
under "havoc". That's because I'm lazy and I didn't want to mess with the UI
too much ;)


## 6) Trimming support

The generic trimming routines implemented in AFLFuzz can easily destroy the
structure of complex formats, possibly leading to a point where you have a lot
of testcases in the queue that your Python module cannot process anymore but
your target application still accepts. This is especially the case when your
target can process a part of the input (causing coverage) and then errors out
on the remaining input.

In such cases, it makes sense to implement a custom trimming routine in Python.
The API consists of multiple methods because after each trimming step, we have
to go back into the C code to check if the coverage bitmap is still the same
for the trimmed input. Here's a quick API description:

init_trim: This method is called at the start of each trimming operation
           and receives the initial buffer. It should return the amount
           of iteration steps possible on this input (e.g. if your input
           has n elements and you want to remove them one by one, return n,
           if you do a binary search, return log(n), and so on...).

           If your trimming algorithm doesn't allow you to determine the
           amount of (remaining) steps easily (esp. while running), then you
           can alternatively return 1 here and always return 0 in post_trim
           until you are finished and no steps remain. In that case,
           returning 1 in post_trim will end the trimming routine. The whole
           current index/max iterations stuff is only used to show progress.

trim:      This method is called for each trimming operation. It doesn't
           have any arguments because we already have the initial buffer
           from init_trim and we can memorize the current state in global
           variables. This can also save reparsing steps for each iteration.
           It should return the trimmed input buffer, where the returned data
           must not exceed the initial input data in length. Returning anything
           that is larger than the original data (passed to init_trim) will
           result in a fatal abort of AFLFuzz.

post_trim: This method is called after each trim operation to inform you
           if your trimming step was successful or not (in terms of coverage).
           If you receive a failure here, you should reset your input to the
           last known good state.
           In any case, this method must return the next trim iteration index
           (from 0 to the maximum amount of steps you returned in init_trim).

Omitting any of the methods will cause Python trimming to be disabled and
trigger a fallback to the builtin default trimming routine.
