#include <algorithm>
#include <chrono>
#include <cmath>
#include <vector>

#include <boost/random.hpp>

#include "afl-fuzz-rl.h"
#include "types.h"

using namespace boost;

namespace {
static std::vector<float> computeScores(const rl_params_t *RLParams,
                                        CorrectionFactor   CorrectionFact) {
  const auto  MapSize = RLParams->map_size;
  const auto *PosRewards = RLParams->positive_reward;
  const auto *NegRewards = RLParams->negative_reward;

  std::vector<float> Scores(MapSize);
#ifdef _DEBUG
  // Fix RNG seed in debug mode
  random::mt19937 RNG;
#else
  random::mt19937 RNG(std::time(nullptr));
#endif

  for (unsigned I = 0; I < MapSize; ++I) {
    random::beta_distribution<> Dist(PosRewards[I], NegRewards[I]);
    Scores[I] = Dist(RNG);
  }
  assert(Scores.size() == MapSize);

  if (CorrectionFact == CorrectionFactor::WithoutSquareRoot) {
    for (unsigned I = 0; I < MapSize; ++I) {
      const auto PosReward = static_cast<float>(PosRewards[I]);
      const auto NegReward = static_cast<float>(NegRewards[I]);

      const auto Rareness = (PosReward + NegReward) /
                            (std::pow(PosReward, 2) + PosReward + NegReward);
      Scores[I] *= Rareness;
    }
  } else if (CorrectionFact == CorrectionFactor::WithSquareRoot) {
    for (unsigned I = 0; I < MapSize; ++I) {
      const auto PosReward = static_cast<float>(PosRewards[I]);
      const auto NegReward = static_cast<float>(NegRewards[I]);

      const auto Rareness =
          std::sqrt((PosReward + NegReward) /
                    (std::pow(PosReward, 2) + PosReward + NegReward));
      Scores[I] *= Rareness;
    }
  } else if (CorrectionFact == CorrectionFactor::Sample) {
    for (unsigned I = 0; I < MapSize; ++I) {
      const auto PosReward = static_cast<float>(PosRewards[I]);
      const auto NegReward = static_cast<float>(NegRewards[I]);

      random::beta_distribution<> Dist(PosReward + NegReward,
                                       std::pow(PosReward, 2));
      Scores[I] *= Dist(RNG);
    }
  }
  assert(Scores.size() == MapSize);

  return Scores;
}

static u32 SelectBestBit(const rl_params_t *RLParams,
                         CorrectionFactor   CorrectionFact) {
  const auto &Scores = computeScores(RLParams, CorrectionFact);
  const auto  ArgMax = std::max_element(Scores.begin(), Scores.end());
  return std::distance(Scores.begin(), ArgMax);
}
}  // anonymous namespace

extern "C" u32 rl_select_best_bit(const rl_params_t *   rl_params,
                                  enum CorrectionFactor CorrectionFact) {
  return SelectBestBit(rl_params, CorrectionFact);
}
