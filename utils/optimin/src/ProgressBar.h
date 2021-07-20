/**
 *  Progress bar.
 *
 *  Adapted from https://www.bfilipek.com/2020/02/inidicators.html
 */

#pragma once

#include <llvm/ADT/StringRef.h>
#include <llvm/Support/raw_ostream.h>

/// Display a progress bar in the terminal
class ProgressBar {
 private:
  const size_t      BarWidth;
  const std::string Fill;
  const std::string Remainder;

 public:
  ProgressBar() : ProgressBar(60, "#", " ") {
  }

  ProgressBar(size_t Width, const llvm::StringRef F, const llvm::StringRef R)
      : BarWidth(Width), Fill(F), Remainder(R) {
  }

  void update(float Progress, const llvm::StringRef Status = "",
              llvm::raw_ostream &OS = llvm::outs()) {
    // No need to write once progress is 100%
    if (Progress > 100.0f) return;

    // Move cursor to the first position on the same line and flush
    OS << '\r';
    OS.flush();

    // Start bar
    OS << '[';

    const auto Completed =
        static_cast<size_t>(Progress * static_cast<float>(BarWidth) / 100.0);
    for (size_t I = 0; I < BarWidth; ++I) {
      if (I <= Completed) {
        OS << Fill;
      } else {
        OS << Remainder;
      }
    }

    // End bar
    OS << ']';

    // Write progress percentage
    OS << ' ' << std::min(static_cast<size_t>(Progress), size_t(100)) << '%';

    // Write status text
    OS << "  " << Status;
  }
};
