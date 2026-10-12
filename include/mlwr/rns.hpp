#pragma once

#include "openfhe.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace mlwr {
using Integer = lbcrypto::BigInteger;
using RingPoly = lbcrypto::DCRTPoly;
using RnsParams = std::shared_ptr<RingPoly::Params>;

RnsParams MakeRnsParams(uint32_t ring_dimension, const std::vector<uint64_t>& primes);
RnsParams JoinBases(const RnsParams& first, const RnsParams& second);
RnsParams PrefixBasis(const RnsParams& full, std::size_t count);
bool SameBasis(const RnsParams& first, const RnsParams& second);

RingPoly FromCoefficients(const RnsParams& params, const std::vector<Integer>& coefficients,
                          Format format = EVALUATION);
RingPoly FromSignedCoefficients(const RnsParams& params, const std::vector<int64_t>& coefficients,
                                Format format = EVALUATION);
std::vector<Integer> Coefficients(const RingPoly& value);

// Exact nearest-integer modulus conversion of COEFFICIENTS. Reconstructing the
// composite integer is intentional: rounding each RNS residue is not equivalent.
// All supported moduli are odd, so integer ratios never have half-integer ties.
RingPoly ScaleAndRound(const RingPoly& value, const RnsParams& target);
RingPoly LiftCentered(const RingPoly& value, const RnsParams& target);
RingPoly SelectBasis(const RingPoly& value, const RnsParams& subset);
RingPoly MultiplyInteger(const RingPoly& value, const Integer& scalar);
RingPoly Automorphism(const RingPoly& value, uint32_t exponent);
uint32_t RotationExponent(int64_t steps, uint32_t ring_dimension);
}  // namespace mlwr
