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

Profile OpenFheProfile(uint32_t depth = 3, uint32_t slots = 8);
void WriteProfileJson(std::ostream& out, const Profile& profile);
RnsParams IndependentLargerBasis(const RnsParams& model, const RnsParams& exclude = nullptr);
}  // namespace mlwr
