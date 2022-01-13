#include "lpm_aflpp_custom_mutator_input.h"
#include <iostream>
#include <sstream>
#include <fstream>

using std::cin;
using std::cout;
using std::endl;

std::string ProtoToData(const TEST &test_proto) {
    std::stringstream all;
    const auto &aa = test_proto.a();
    const auto &bb = test_proto.b();
    all.write((const char*)&aa, sizeof(aa));
    if(bb.size() != 0) {
        all.write(bb.c_str(), bb.size());
    }

    std::string res = all.str();
    if (bb.size() != 0 && res.size() != 0) {
        // set PROTO_FUZZER_DUMP_PATH env to dump the serialized protobuf
        if (const char *dump_path = getenv("PROTO_FUZZER_DUMP_PATH")) {
            std::ofstream of(dump_path);
            of.write(res.data(), res.size());
        }
    }
    return res;
}

/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Return NULL on error.
 */
extern "C" MyMutator *afl_custom_init(void *afl, unsigned int seed) {
    MyMutator *mutator = new MyMutator();
    
    mutator->RegisterPostProcessor(
        TEST::descriptor(),
        [](google::protobuf::Message* message, unsigned int seed) {
            // libprotobuf-mutator's built-in mutator is kind of....crappy :P
            // Even a dumb fuzz like `TEST.a = rand();` is better in this case... Q_Q
            // We register a post processor to apply our dumb fuzz
            
            TEST *t = static_cast<TEST *>(message);
            t->set_a(rand());
        });

    srand(seed);
    return mutator;
}

/**
 * Perform custom mutations on a given input
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to input data to be mutated
 * @param[in] buf_size Size of input data
 * @param[out] out_buf the buffer we will work on. we can reuse *buf. NULL on
 * error.
 * @param[in] add_buf Buffer containing the additional test case
 * @param[in] add_buf_size Size of the additional test case
 * @param[in] max_size Maximum size of the mutated output. The mutation must not
 *     produce data larger than max_size.
 * @return Size of the mutated output.
 */
extern "C" size_t afl_custom_fuzz(MyMutator *mutator, // return value from afl_custom_init
                       uint8_t *buf, size_t buf_size, // input data to be mutated
                       uint8_t **out_buf, // output buffer
                       uint8_t *add_buf, size_t add_buf_size,  // add_buf can be NULL
                       size_t max_size) {
    // This function can be named either "afl_custom_fuzz" or "afl_custom_mutator"
    // A simple test shows that "buf" will be the content of the current test case
    // "add_buf" will be the next test case ( from AFL++'s input queue )
    
    TEST input;
    // parse input data to TEST
    // Notice that input data should be a serialized protobuf data
    // Check ./in/ii and test_protobuf_serializer for more detail
    bool parse_ok = input.ParseFromArray(buf, buf_size);
    if(!parse_ok) {
        // Invalid serialize protobuf data. Don't mutate.
        // Return a dummy buffer. Also mutated_size = 0
        static uint8_t *dummy = new uint8_t[10]; // dummy buffer with no data
        *out_buf = dummy;
        return 0;
    }
    // mutate the protobuf
    mutator->Mutate(&input, max_size);
    
    // Convert protobuf to raw data
    const TEST *p = &input;
    std::string s = ProtoToData(*p);
    // Copy to a new buffer ( mutated_out )
    size_t mutated_size = s.size() <= max_size ? s.size() : max_size; // check if raw data's size is larger than max_size

    delete[] mutator->mutated_out;
    mutator->mutated_out = new uint8_t[mutated_size];
    memcpy(mutator->mutated_out, s.c_str(), mutated_size); // copy the mutated data
    // Assign the mutated data and return mutated_size
    *out_buf = mutator->mutated_out;
    return mutated_size;
}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
extern "C" void afl_custom_deinit(void *data) {
    // Honestly I don't know what to do with this...
    return;
}

