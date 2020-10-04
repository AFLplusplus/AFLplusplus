

extern "C" ATTRIBUTE_INTERFACE void
LLVMFuzzerMyInit(int (*Callback)(const uint8_t *Data, size_t Size), unsigned int Seed) {
  Random Rand(Seed);
  FuzzingOptions Options;
  Options.Verbosity = 3;
  Options.MaxLen = 1024000;
  Options.LenControl = true;
  Options.DoCrossOver = false;
  Options.MutateDepth = 6;
  Options.UseCounters = false;
  Options.UseMemmem = false;
  Options.UseCmp = false;
  Options.UseValueProfile = false;
  Options.Shrink = false;
  Options.ReduceInputs = false;
  Options.PreferSmall = false;
  Options.ReloadIntervalSec = 0;
  Options.OnlyASCII = false;
  Options.DetectLeaks = false;
  Options.PurgeAllocatorIntervalSec = 0;
  Options.TraceMalloc = false;
  Options.RssLimitMb = 100;
  Options.MallocLimitMb = 100;
  Options.MaxNumberOfRuns = 0;
  Options.ReportSlowUnits = false;
  Options.Entropic = false;
  
  struct EntropicOptions Entropic;
  Entropic.Enabled = Options.Entropic;
  EF = new ExternalFunctions();
  auto *MD = new MutationDispatcher(Rand, Options);
  auto *Corpus = new InputCorpus(Options.OutputCorpus, Entropic);
  auto *F = new Fuzzer(Callback, *Corpus, *MD, Options);
}
