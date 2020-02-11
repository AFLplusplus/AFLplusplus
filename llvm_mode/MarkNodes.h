#ifndef __MARK_NODES__
#define __MARK_NODES__

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include <vector>

std::pair<std::vector<llvm::BasicBlock *>, std::vector<llvm::BasicBlock *>> markNodes(llvm::Function *F);
std::pair<std::vector<llvm::BasicBlock *>, std::vector<llvm::BasicBlock *>> markNodesGlobally(llvm::Module &M);

#endif

