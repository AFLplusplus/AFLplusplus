#include <src/mutator.h>
#include "test.pb.h"

class MyMutator : public protobuf_mutator::Mutator {
public:
    uint8_t *mutated_out = nullptr; 
    ~MyMutator() {
        delete[] mutated_out;
    }
};
