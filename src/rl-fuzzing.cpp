#include <algorithm>
#include <chrono>
#include <cmath>
#include <vector>

#include <boost/random.hpp>
#include <boost/random/beta_distribution.hpp>

#include "afl-fuzz-rl.h"
#include "types.h"

using namespace boost;

namespace {
static std::vector<float> computeScores(const rl_params_t *RLParams) {
  const auto  CorrectionFactor = RLParams->correction_factor;
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
    switch (CorrectionFactor) {
      case rl_correction_factor_t::WO_RARENESS:
        return [&](float, float) -> float { return 1; };
      case rl_correction_factor_t::WITH_RARENESS:
        return [&](float Pos, float Neg) -> float {
          return (Pos + Neg) / (std::pow(Pos, 2) + Pos + Neg);
        };
      case rl_correction_factor_t::WITH_SQUARE_ROOT:
        return [&](float Pos, float Neg) -> float {
          return std::sqrt((Pos + Neg) / (std::pow(Pos, 2) + Pos + Neg));
        };
      case rl_correction_factor_t::SAMPLE_RARENESS:
        return [&](float Pos, float Neg) -> float {
          return random::beta_distribution<>(Pos + Neg, std::pow(Pos, 2))(RNG);
        };
      case rl_correction_factor_t::RARE_WO_RL:
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

    if (CorrectionFactor == rl_correction_factor_t::RARE_EDGE) {
      Scores[I] = Rareness;
    } else {
      random::beta_distribution<> Dist(PosReward, NegReward);
      Scores[I] = Dist(RNG) * Rareness;
    }
  }
#ifdef _DEBUG
  assert(Scores.size() == MapSize);
#endif

  return Scores;
}

static u32 SelectBestBit(const rl_params_t *RLParams) {
  const auto &Scores = computeScores(RLParams);
  const auto  ArgMax = std::max_element(Scores.begin(), Scores.end());

  return std::distance(Scores.begin(), ArgMax);
}
}  // anonymous namespace

extern "C" u32 rl_select_best_bit(const rl_params_t *rl_params) {
  return SelectBestBit(rl_params);
}
