# AFL++ documentation

This is the overview of the AFL++ docs content.

For general information on AFL++, see the
[README.md of the repository](../README.md).

Also take a look at our [FAQ.md](FAQ.md) and
[best_practices.md](best_practices.md).

## Fuzzing targets with the source code available

You can find a quickstart for fuzzing targets with the source code available in
the [README.md of the repository](../README.md#quick-start-fuzzing-with-afl).

For in-depth information on the steps of the fuzzing process, see
[fuzzing_in_depth.md](fuzzing_in_depth.md) or click on the following
image and select a step.

![Fuzzing process overview](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/dev/docs/resources/0_fuzzing_process_overview.drawio.svg "Fuzzing process overview")

For further information on instrumentation, see the
[READMEs in the instrumentation/ folder](../instrumentation/).

### Instrumenting the target

For more information, click on the following image and select a step.

![Instrumenting the target](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/dev/docs/resources/1_instrument_target.drawio.svg "Instrumenting the target")

### Preparing the fuzzing campaign

For more information, click on the following image and select a step.

![Preparing the fuzzing campaign](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/dev/docs/resources/2_prepare_campaign.drawio.svg "Preparing the fuzzing campaign")

### Fuzzing the target

For more information, click on the following image and select a step.

![Fuzzing the target](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/dev/docs/resources/3_fuzz_target.drawio.svg "Fuzzing the target")

### Managing the fuzzing campaign

For more information, click on the following image and select a step.

![Managing the fuzzing campaign](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/dev/docs/resources/4_manage_campaign.drawio.svg "Managing the fuzzing campaign")

## Fuzzing other targets

To learn about fuzzing other targets, see:

* Binary-only: [fuzzing_binary-only_targets.md](fuzzing_binary-only_targets.md)
* GUI programs:
  [best_practices.md#fuzzing-a-gui-program](best_practices.md#fuzzing-a-gui-program)
* Libraries: [frida_mode/README.md](../frida_mode/README.md)
* Network services:
  [best_practices.md#fuzzing-a-network-service](best_practices.md#fuzzing-a-network-service)
* Non-linux: [unicorn_mode/README.md](../unicorn_mode/README.md)

## Additional information

* Tools that help fuzzing with AFL++:
  [third_party_tools.md](third_party_tools.md)
* Tutorials: [tutorials.md](tutorials.md)