# Common sense risks

Please keep in mind that, similarly to many other computationally-intensive
tasks, fuzzing may put a strain on your hardware and on the OS. In particular:

  - Your CPU will run hot and will need adequate cooling. In most cases, if
    cooling is insufficient or stops working properly, CPU speeds will be
    automatically throttled. That said, especially when fuzzing on less
    suitable hardware (laptops, smartphones, etc), it's not entirely impossible
    for something to blow up.

  - Targeted programs may end up erratically grabbing gigabytes of memory or
    filling up disk space with junk files. AFL++ tries to enforce basic memory
    limits, but can't prevent each and every possible mishap. The bottom line
    is that you shouldn't be fuzzing on systems where the prospect of data loss
    is not an acceptable risk.

  - Fuzzing involves billions of reads and writes to the filesystem. On modern
    systems, this will be usually heavily cached, resulting in fairly modest
    "physical" I/O - but there are many factors that may alter this equation.
    It is your responsibility to monitor for potential trouble; with very heavy
    I/O, the lifespan of many HDDs and SSDs may be reduced.

    A good way to monitor disk I/O on Linux is the 'iostat' command:

```shell
    $ iostat -d 3 -x -k [...optional disk ID...]
```

    Using the `AFL_TMPDIR` environment variable and a RAM-disk you can have the
    heavy writing done in RAM to prevent the aforementioned wear and tear. For
    example the following line will run a Docker container with all this preset:
    
    ```shell
    # docker run -ti --mount type=tmpfs,destination=/ramdisk -e AFL_TMPDIR=/ramdisk aflplusplus/aflplusplus
    ```