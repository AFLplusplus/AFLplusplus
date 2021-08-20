# Restructure AFL++'s documentation

## About us

We are dedicated to everything around fuzzing, our main and most well known
contribution is the fuzzer `AFL++` which is part of all major Unix
distributions (e.g. Debian, Arch, FreeBSD, etc.) and is deployed on Google's
oss-fuzz and clusterfuzz. It is rated the top fuzzer on Google's fuzzbench.

We are four individuals from Europe supported by a large community.

All our tools are open source.

## About the AFL++ fuzzer project

AFL++ inherited it's documentation from the original Google AFL project.
Since then it has been massively improved - feature and performance wise -
and although the documenation has likewise been continued it has grown out
of proportion.
The documentation is done by non-natives to the English language, plus
none of us has a writer background.

We see questions on AFL++ usage on mailing lists (e.g. afl-users), discord
channels, web forums and as issues in our repository.

This only increases as AFL++ has been on the top of Google's fuzzbench
statistics (which measures the performance of fuzzers) and is now being
integrated in Google's oss-fuzz and clusterfuzz - and is in many Unix
packaging repositories, e.g. Debian, FreeBSD, etc.

AFL++ now has 44 (!) documentation files with 13k total lines of content.
This is way too much.

Hence AFL++ needs a complete overhaul of it's documentation, both on a 
organisation/structural level as well as the content.

Overall the following actions have to be performed:
  * Create a better structure of documentation so it is easier to find the
    information that is being looked for, combining and/or splitting up the
    existing documents as needed.
  * Rewrite some documentation to remove duplication. Several information is
    present several times in the documentation. These should be removed to
    where needed so that we have as little bloat as possible.
  * The documents have been written and modified by a lot of different people,
    most of them non-native English speaker. Hence an overall review where
    parts should be rewritten has to be performed and then the rewrite done.
  * Create a cheat-sheet for a very short best-setup build and run of AFL++
  * Pictures explain more than 1000 words. We need at least 4 images that
    explain the workflow with AFL++:
      - the build workflow
      - the fuzzing workflow
      - the fuzzing campaign management workflow
      - the overall workflow that is an overview of the above
      - maybe more? where the technical writes seems it necessary for
        understanding.

Requirements:
  * Documentation has to be in Markdown format
  * Images have to be either in SVG or PNG format.
  * All documentation should be (moved) in(to) docs/

The project does not require writing new documentation or tutorials beside the
cheat sheet. The technical information for the cheat sheet will be provided by
us.

## Metrics

AFL++ is a the highest performant fuzzer publicly available - but is also the
most feature rich and complex. With the publicity of AFL++' success and
deployment in Google projects internally and externally and availability as
a package on most Linux distributions we see more and more issues being
created and help requests on our Discord channel that would not be
necessary if people would have read through all our documentation - which
is unrealistic.

We expect the the new documenation after this project to be cleaner, easier
accessible and lighter to digest by our users, resulting in much less
help requests. On the other hand the amount of users using AFL++ should
increase as well as it will be more accessible which would also increase
questions again - but overall resulting in a reduction of help requests.

In numbers: we currently have per week on average 5 issues on Github,
10 questions on discord and 1 on mailing lists that would not be necessary
with perfect documentation and perfect people.

We would consider this project a success if afterwards we only have
2 issues on Github and 3 questions on discord anymore that would be answered
by reading the documentation. The mailing list is usually used by the most
novice users and we don't expect any less questions there.

## Project Budget

We have zero experience with technical writers, so this is very hard for us
to calculate. We expect it to be a lot of work though because of the amount
of documentation we have that needs to be restructured and partially rewritten
(44 documents with 13k total lines of content).

We assume the daily rate of a very good and experienced technical writer in
times of a pandemic to be ~500$ (according to web research), and calculate
the overall amout of work to be around 20 days for everything incl. the
graphics (but again - this is basically just guessing).

Technical Writer                                              10000$
Volunteer stipends                                                0$ (waved)
T-Shirts for the top 10 contributors and helpers to this documentation project:
	10 AFL++ logo t-shirts 		20$ each		200$
	10 shipping cost of t-shirts    10$ each		100$

Total: 10.300$
(in the submission form 10.280$ was entered)

## Additional Information

We have participated in Google Summer of Code in 2020 and hope to be selected
again in 2021.

We have no experience with a technical writer, but we will support that person
with video calls, chats, emails and messaging, provide all necessary information
and write technical contents that is required for the success of this project.
It is clear to us that a technical writer knows how to write, but cannot know
the technical details in a complex tooling like in AFL++. This guidance, input,
etc. has to come from us.
