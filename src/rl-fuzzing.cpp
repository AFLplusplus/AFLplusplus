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

  const auto &CalcRareness = [&]() -> std::function<float(float, float)> {
    switch (CorrectionFact) {
      case CorrectionFactor::None:
        return [&](float, float) -> float { return 1; };
      case CorrectionFactor::WithoutSquareRoot:
        return [&](float Pos, float Neg) -> float {
          return (Pos + Neg) / (std::pow(Pos, 2) + Pos + Neg);
        };
      case CorrectionFactor::WithSquareRoot:
        return [&](float Pos, float Neg) -> float {
          return std::sqrt((Pos + Neg) / (std::pow(Pos, 2) + Pos + Neg));
        };
      case CorrectionFactor::Sample:
        return [&](float Pos, float Neg) -> float {
          return random::beta_distribution<>(Pos + Neg, std::pow(Pos, 2))(RNG);
        };
      default:
        __builtin_unreachable();
    }
  }();

  for (unsigned I = 0; I < MapSize; ++I) {
    const auto                  PosReward = static_cast<float>(PosRewards[I]);
    const auto                  NegReward = static_cast<float>(NegRewards[I]);
    const auto                  Rareness = CalcRareness(PosReward, NegReward);
    random::beta_distribution<> Dist(PosReward, NegReward);

    Scores[I] = Dist(RNG) * Rareness;
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
