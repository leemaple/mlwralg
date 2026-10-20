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
    bool compact = false;
    uint32_t gadget_bits = 20, public_extra_bits = 20;
    uint32_t checked_public_bits = 0;
    uint32_t rotation_gadget_bits = 14;
    bool symmetric_relinearization = false;
    uint32_t standard_gadget_bits = 0; // zero retains the original one-digit GHS path
    bool packed_public_key = false;
};

// N=0 preserves OpenFHE's security-table selection; a nonzero N is still
// checked against that table. The table is not a proof for this construction.
void ValidateProfileOptions(uint32_t depth, uint32_t slots, uint32_t ring_dimension,
                            uint32_t scale_bits, uint32_t first_mod_bits, uint32_t security_bits = 128,
                            bool compact = false);
Profile OpenFheProfile(uint32_t depth = 3, uint32_t slots = 8, uint32_t ring_dimension = 0,
                       uint32_t scale_bits = 50, uint32_t first_mod_bits = 60, uint32_t security_bits = 128);
void WriteProfileJson(std::ostream& out, const Profile& profile);
RnsParams IndependentLargerBasis(const RnsParams& model, const RnsParams& exclude = nullptr,
                                uint32_t extra_bits = 30, bool small_extra = false);
RnsParams PackedLargerBasis(const RnsParams& model, uint32_t extra_bits);
Profile CompactProfile(uint32_t depth, uint32_t slots, uint32_t n, uint32_t scale_bits,
                       uint32_t first_bits, uint32_t security_bits, uint32_t divisor_bits,
                       uint32_t gadget_bits, uint32_t public_extra_bits, uint32_t rotation_gadget_bits = 14,
                       double scale_log2 = 0, bool packed_public_key = false);
}  // namespace mlwr
