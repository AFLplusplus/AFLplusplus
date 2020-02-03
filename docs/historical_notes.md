# Historical notes

  This doc talks about the rationale of some of the high-level design decisions
  for American Fuzzy Lop. It's adopted from a discussion with Rob Graham.
  See README.md for the general instruction manual, and technical_details.md for
  additional implementation-level insights.

## 1) Influences

In short, `afl-fuzz` is inspired chiefly by the work done by Tavis Ormandy back
in 2007. Tavis did some very persuasive experiments using `gcov` block coverage
to select optimal test cases out of a large corpus of data, and then using
them as a starting point for traditional fuzzing workflows.

(By "persuasive", I mean: netting a significant number of interesting
vulnerabilities.)

In parallel to this, both Tavis and I were interested in evolutionary fuzzing.
Tavis had his experiments, and I was working on a tool called bunny-the-fuzzer,
released somewhere in 2007.

Bunny used a generational algorithm not much different from `afl-fuzz`, but
also tried to reason about the relationship between various input bits and
the internal state of the program, with hopes of deriving some additional value
from that. The reasoning / correlation part was probably in part inspired by
other projects done around the same time by Will Drewry and Chris Evans.

The state correlation approach sounded very sexy on paper, but ultimately, made
the fuzzer complicated, brittle, and cumbersome to use; every other target
program would require a tweak or two. Because Bunny didn't fare a whole lot
better than less sophisticated brute-force tools, I eventually decided to write
it off. You can still find its original documentation at:

  https://code.google.com/p/bunny-the-fuzzer/wiki/BunnyDoc

There has been a fair amount of independent work, too. Most notably, a few
weeks earlier that year, Jared DeMott had a Defcon presentation about a
coverage-driven fuzzer that relied on coverage as a fitness function.

Jared's approach was by no means identical to what afl-fuzz does, but it was in
the same ballpark. His fuzzer tried to explicitly solve for the maximum coverage
with a single input file; in comparison, afl simply selects for cases that do
something new (which yields better results - see [technical_details.md](technical_details.md)).

A few years later, Gabriel Campana released fuzzgrind, a tool that relied purely
on Valgrind and a constraint solver to maximize coverage without any brute-force
bits; and Microsoft Research folks talked extensively about their still
non-public, solver-based SAGE framework.

In the past six years or so, I've also seen a fair number of academic papers
that dealt with smart fuzzing (focusing chiefly on symbolic execution) and a
couple papers that discussed proof-of-concept applications of genetic
algorithms with the same goals in mind. I'm unconvinced how practical most of
these experiments were; I suspect that many of them suffer from the
bunny-the-fuzzer's curse of being cool on paper and in carefully designed
experiments, but failing the ultimate test of being able to find new,
worthwhile security bugs in otherwise well-fuzzed, real-world software.

In some ways, the baseline that the "cool" solutions have to compete against is
a lot more impressive than it may seem, making it difficult for competitors to
stand out. For a singular example, check out the work by Gynvael and Mateusz
Jurczyk, applying "dumb" fuzzing to ffmpeg, a prominent and security-critical
component of modern browsers and media players:

  http://googleonlinesecurity.blogspot.com/2014/01/ffmpeg-and-thousand-fixes.html

Effortlessly getting comparable results with state-of-the-art symbolic execution
in equally complex software still seems fairly unlikely, and hasn't been
demonstrated in practice so far.

But I digress; ultimately, attribution is hard, and glorying the fundamental
concepts behind AFL is probably a waste of time. The devil is very much in the
often-overlooked details, which brings us to...

## 2. Design goals for afl-fuzz

In short, I believe that the current implementation of afl-fuzz takes care of
several itches that seemed impossible to scratch with other tools:

1) Speed. It's genuinely hard to compete with brute force when your "smart"
   approach is resource-intensive. If your instrumentation makes it 10x more
   likely to find a bug, but runs 100x slower, your users are getting a bad
   deal.

   To avoid starting with a handicap, `afl-fuzz` is meant to let you fuzz most of
   the intended targets at roughly their native speed - so even if it doesn't
   add value, you do not lose much.

   On top of this, the tool leverages instrumentation to actually reduce the
   amount of work in a couple of ways: for example, by carefully trimming the
   corpus or skipping non-functional but non-trimmable regions in the input
   files.

2) Rock-solid reliability. It's hard to compete with brute force if your
   approach is brittle and fails unexpectedly. Automated testing is attractive
   because it's simple to use and scalable; anything that goes against these
   principles is an unwelcome trade-off and means that your tool will be used
   less often and with less consistent results.

   Most of the approaches based on symbolic execution, taint tracking, or
   complex syntax-aware instrumentation are currently fairly unreliable with
   real-world targets. Perhaps more importantly, their failure modes can render
   them strictly worse than "dumb" tools, and such degradation can be difficult
   for less experienced users to notice and correct.

   In contrast, `afl-fuzz` is designed to be rock solid, chiefly by keeping it
   simple. In fact, at its core, it's designed to be just a very good
   traditional fuzzer with a wide range of interesting, well-researched
   strategies to go by. The fancy parts just help it focus the effort in
   places where it matters the most.

3) Simplicity. The author of a testing framework is probably the only person
   who truly understands the impact of all the settings offered by the tool -
   and who can dial them in just right. Yet, even the most rudimentary fuzzer
   frameworks often come with countless knobs and fuzzing ratios that need to
   be guessed by the operator ahead of the time. This can do more harm than 
   good.

   AFL is designed to avoid this as much as possible. The three knobs you
   can play with are the output file, the memory limit, and the ability to
   override the default, auto-calibrated timeout. The rest is just supposed to
   work. When it doesn't, user-friendly error messages outline the probable
   causes and workarounds, and get you back on track right away.

4) Chainability. Most general-purpose fuzzers can't be easily employed
   against resource-hungry or interaction-heavy tools, necessitating the
   creation of custom in-process fuzzers or the investment of massive CPU
   power (most of which is wasted on tasks not directly related to the code
   we actually want to test).

   AFL tries to scratch this itch by allowing users to use more lightweight
   targets (e.g., standalone image parsing libraries) to create small
   corpora of interesting test cases that can be fed into a manual testing
   process or a UI harness later on.

As mentioned in [technical_details.md](technical_details.md), AFL does all this not by systematically
applying a single overarching CS concept, but by experimenting with a variety
of small, complementary methods that were shown to reliably yields results
better than chance. The use of instrumentation is a part of that toolkit, but is
far from being the most important one.

Ultimately, what matters is that `afl-fuzz` is designed to find cool bugs - and
has a pretty robust track record of doing just that.
