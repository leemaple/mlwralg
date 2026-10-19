#pragma once

#include "mlwr/rns.hpp"
#include <iosfwd>

namespace mlwr {
// Shared numerical workload, including the one-digit HYBRID auxiliary basis.
// OpenFHE's RLWE security selector does NOT certify this MLWR construction.
struct Profile {
    lbcrypto::CryptoContext<RingPoly> encoder;
    RnsParams ciphertext;
    RnsParams auxiliary;
    uint32_t depth;
    uint32_t slots;
};

// N=0 preserves OpenFHE's security-table selection; a nonzero N is still
// checked against that table. The table is not a proof for this construction.
void ValidateProfileOptions(uint32_t depth, uint32_t slots, uint32_t ring_dimension,
                            uint32_t scale_bits, uint32_t first_mod_bits, uint32_t security_bits = 128);
Profile OpenFheProfile(uint32_t depth = 3, uint32_t slots = 8, uint32_t ring_dimension = 0,
                       uint32_t scale_bits = 50, uint32_t first_mod_bits = 60, uint32_t security_bits = 128);
void WriteProfileJson(std::ostream& out, const Profile& profile);
RnsParams IndependentLargerBasis(const RnsParams& model, const RnsParams& exclude = nullptr);
}  // namespace mlwr
