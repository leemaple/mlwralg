#pragma once

#include "mlwr/profile.hpp"
#include <string>

namespace mlwr {
struct RunOptions {
    uint32_t l = 2, k = 2, n = 0, depth = 3, slots = 8;
    uint32_t scale_bits = 50, first_mod_bits = 60;
    uint32_t samples = 15, warmups = 2;
    uint32_t security_bits = 128, precision_bits = 20, key_trials = 3, message_seed = 20261013;
    uint32_t smudge_bound = 0;
    uint32_t initial_scale_bits = 0;
    int32_t rotation_steps = 1;
    double message_bound = 2;
    bool help = false, print_parameters = false;
    bool compact = false;
    uint32_t divisor_bits = 20, gadget_bits = 20, public_extra_bits = 20;
    uint32_t rotation_gadget_bits = 14;
    Profile MakeProfile() const;
    double EncodingScale() const;
};

// Priority: built-in defaults < one UTF-8 key=value config < named flags.
// Legacy experiment positional sample/warmup arguments remain accepted.
RunOptions ParseOptions(int argc, char** argv, bool experiment = false);
void WriteOptionsJson(std::ostream& out, const RunOptions& options);
void PrintOptionsHelp(std::ostream& out, bool experiment = false);
}  // namespace mlwr
