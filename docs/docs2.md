# Restructure AFL++'s documentation - Case Study

## Problem statement

AFL++ inherited it's documentation from the original Google AFL project.
Since then it has been massively improved - feature and performance wise -
and although the documenation has likewise been continued it has grown out
of proportion.
The documentation is done by non-natives to the English language, plus
none of us has a writer background.

We see questions on AFL++ usage on mailing lists (e.g. afl-users), discord
channels, web forums and as issues in our repository.
Most of them could be answered if people would read through all the
documentation.

This only increases as AFL++ has been on the top of Google's fuzzbench
statistics (which measures the performance of fuzzers) and has been
integrated in Google's oss-fuzz and clusterfuzz - and is in many Unix
packaging repositories, e.g. Debian, FreeBSD, etc.

AFL++ had 44 (!) documentation files with 13k total lines of content.
This was way too much.

## Proposal abstract

AFL++'s documentatin needs a complete overhaul, both on a
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

## Project description

We created our proposal by discussing in the team what the issues are and
what was needed to fix it.
This resulted in the [project proposal](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/docs.md).

We did not want to be selected by a writer but select a writer ourselves, so
we combed through the list and reviewed every single one of them.
We were not looking for coders writing technical documentation, but rather
someone who is an experienced writer and has documented experience with
structuring documentation.
Few fit that profile and we sent out messages to 6 people.
We finally decided on Jana because she had a strong background in technical
documentation and structuring information.
She had no technical experience in fuzzing whatsoever, but we saw that as
a plus - of course this made the whole process longer to explain details,
but overall ensured that the documentation can be read by (mostly) everyone.

We communicated via video calls every few weeks and she kept a public kanban
board about her todos, additional we used a Signal channel.
Her changes were imported via PRs where we discussed details.

The project was off to a good start, but then Jana got pregnant with serious
side effects that made working impossible for her for a longer time, hence
the schedule was thrown back.
She offered to rescind the payment and we select a new writer, but we saw
little opportunity in that, as that would mean a new selection of a writer,
someone else with a different vision on how the result should look like so
basically a full restart of the project and a large impact on our own time.
So we agreed on - after discussion with the Google GSoD team - that she
continues the project after the GSoD completion deadline as best as she can.

End of November she took one week off from work and fully dedicated her time
for the documenation which brought the project a big step forward.

Originally the project should have been ended begin of October, but now - at
nearing the end of November, we are at about 85% completion, with the end
being expected around mid of December.

## Metrics

We merged most of the changes in our development branch and are getting 
close to a state where the user documentation part is completed and we
can create a new release. Only then the new documentatin is actually visible
to users. Therefore no metrics could be collected so far.

We plan on a user-assisted QA review end of November/begin of December.

The documentation was reviewed by a few test users so far however who gave
it a thumbs up.

## Summary

The GSoD project itself is great. It helps to get the documentation back in
line.
It was and is a larger time investment from our side, but we expected that.
When the project is done, the documentation will be more accessible by users
and also need less maintenance by us.
There is still follow-up work to be done by us afterwards (web site for the
docs, etc.).

Not sure what we would do differently next time. I think we prepared best as
possible and reacted best as possible to the unexpected.

Recommendations for other organizations who would like to participate in GSoD:
 - expect the process to take a larger part of your time. the writer needs
   your full support.
 - have someone dedicated from the dev/org side to support, educate and
   supervice the writer
 - set clear goals and expectations
