#include "mlwr/rns.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace mlwr {
namespace {
void ValidateParams(const RnsParams& params) {
    if (!params || params->GetParams().empty()) {
        throw std::invalid_argument("An RNS basis must contain at least one prime");
    }
}

void SameRing(const RnsParams& a, const RnsParams& b) {
    ValidateParams(a);
    ValidateParams(b);
    if (a->GetCyclotomicOrder() != b->GetCyclotomicOrder()) {
        throw std::invalid_argument("RNS conversions require the same polynomial ring");
    }
}
}  // namespace

RnsParams MakeRnsParams(uint32_t n, const std::vector<uint64_t>& primes) {
    if (n < 2 || (n & (n - 1)) || n > (std::numeric_limits<uint32_t>::max() / 2)) {
        throw std::invalid_argument("Ring dimension must be a power of two >= 2");
    }
    if (primes.empty()) throw std::invalid_argument("Empty RNS prime list");
    std::vector<lbcrypto::NativeInteger> moduli;
    for (auto q : primes) {
        if (q >= (uint64_t{1} << 60) || q < 3 || (q - 1) % (2 * n) != 0 ||
            !lbcrypto::MillerRabinPrimalityTest(lbcrypto::NativeInteger(q))) {
            throw std::invalid_argument("RNS prime must be < 2^60 and equal to 1 mod 2N");
        }
        if (std::find(moduli.begin(), moduli.end(), lbcrypto::NativeInteger(q)) != moduli.end()) {
            throw std::invalid_argument("RNS primes must be distinct");
        }
        moduli.emplace_back(q);
    }
    return std::make_shared<RingPoly::Params>(2 * n, moduli);
}

RnsParams JoinBases(const RnsParams& first, const RnsParams& second) {
    SameRing(first, second);
    auto params = first->GetParams();
    for (const auto& tower : second->GetParams()) {
        for (const auto& existing : params) {
            if (existing->GetModulus() == tower->GetModulus()) {
                throw std::invalid_argument("Cannot join overlapping RNS bases");
            }
        }
        params.push_back(tower);
    }
    return std::make_shared<RingPoly::Params>(first->GetCyclotomicOrder(), params);
}

RnsParams PrefixBasis(const RnsParams& full, std::size_t count) {
    ValidateParams(full);
    if (!count || count > full->GetParams().size()) {
        throw std::invalid_argument("Invalid number of RNS towers");
    }
    auto params = full->GetParams();
    params.resize(count);
    return std::make_shared<RingPoly::Params>(full->GetCyclotomicOrder(), params);
}

bool SameBasis(const RnsParams& a, const RnsParams& b) {
    if (!a || !b || a->GetCyclotomicOrder() != b->GetCyclotomicOrder() ||
        a->GetParams().size() != b->GetParams().size()) return false;
    for (std::size_t i = 0; i < a->GetParams().size(); ++i) {
        if (a->GetParams()[i]->GetModulus() != b->GetParams()[i]->GetModulus() ||
            a->GetParams()[i]->GetRootOfUnity() != b->GetParams()[i]->GetRootOfUnity()) return false;
    }
    return true;
}

RingPoly FromCoefficients(const RnsParams& params, const std::vector<Integer>& coefficients,
                          Format format) {
    ValidateParams(params);
    if (coefficients.size() != params->GetRingDimension()) {
        throw std::invalid_argument("Coefficient count must equal ring dimension");
    }
    RingPoly out(params, COEFFICIENT, true);
    for (std::size_t j = 0; j < params->GetParams().size(); ++j) {
        const auto q = params->GetParams()[j]->GetModulus();
        const Integer big_q(q.ConvertToInt());
        lbcrypto::NativeVector residues(coefficients.size(), q);
        for (std::size_t i = 0; i < coefficients.size(); ++i) {
            residues[i] = lbcrypto::NativeInteger(coefficients[i].Mod(big_q).ConvertToInt());
        }
        lbcrypto::NativePoly element(params->GetParams()[j], COEFFICIENT, true);
        element.SetValues(std::move(residues), COEFFICIENT);
        out.SetElementAtIndex(j, std::move(element));
    }
    out.SetFormat(format);
    return out;
}

RingPoly FromSignedCoefficients(const RnsParams& params, const std::vector<int64_t>& coefficients,
                                Format format) {
    ValidateParams(params);
    const auto& modulus = params->GetModulus();
    std::vector<Integer> values;
    values.reserve(coefficients.size());
    for (int64_t x : coefficients) {
        const uint64_t magnitude = x < 0 ? uint64_t(-(x + 1)) + 1 : uint64_t(x);
        auto residue = Integer(magnitude).Mod(modulus);
        values.push_back(x < 0 && residue != Integer(0) ? modulus - residue : residue);
    }
    return FromCoefficients(params, values, format);
}

std::vector<Integer> Coefficients(const RingPoly& value) {
    auto coefficient = value;
    coefficient.SetFormat(COEFFICIENT);
    const auto interpolated = coefficient.CRTInterpolate();
    std::vector<Integer> result;
    result.reserve(interpolated.GetLength());
    for (std::size_t i = 0; i < interpolated.GetLength(); ++i) result.push_back(interpolated[i]);
    return result;
}

RingPoly ScaleAndRound(const RingPoly& value, const RnsParams& target) {
    SameRing(value.GetParams(), target);
    const auto& from = value.GetParams()->GetModulus();
    const auto& to = target->GetModulus();
    const Integer half = from >> 1;
    auto coefficients = Coefficients(value);
    for (auto& x : coefficients) x = ((x * to + half) / from).Mod(to);
    return FromCoefficients(target, coefficients, value.GetFormat());
}

RingPoly LiftCentered(const RingPoly& value, const RnsParams& target) {
    SameRing(value.GetParams(), target);
    const auto& from = value.GetParams()->GetModulus();
    const auto& to = target->GetModulus();
    const Integer half = from >> 1;
    auto coefficients = Coefficients(value);
    for (auto& x : coefficients) {
        if (x > half) {
            const auto magnitude = (from - x).Mod(to);
            x = magnitude == Integer(0) ? magnitude : to - magnitude;
        } else {
            x = x.Mod(to);
        }
    }
    return FromCoefficients(target, coefficients, value.GetFormat());
}

RingPoly SelectBasis(const RingPoly& value, const RnsParams& subset) {
    SameRing(value.GetParams(), subset);
    RingPoly out(subset, value.GetFormat(), true);
    const auto& old = value.GetParams()->GetParams();
    for (std::size_t i = 0; i < subset->GetParams().size(); ++i) {
        const auto& wanted = subset->GetParams()[i];
        auto found = std::find_if(old.begin(), old.end(), [&](const auto& p) {
            return p->GetModulus() == wanted->GetModulus() && p->GetRootOfUnity() == wanted->GetRootOfUnity();
        });
        if (found == old.end()) throw std::invalid_argument("Requested basis is not a subset");
        out.SetElementAtIndex(i, value.GetElementAtIndex(std::distance(old.begin(), found)));
    }
    return out;
}

RingPoly MultiplyInteger(const RingPoly& value, const Integer& scalar) {
    std::vector<lbcrypto::NativeInteger> factors;
    for (const auto& tower : value.GetParams()->GetParams()) {
        factors.emplace_back(scalar.Mod(Integer(tower->GetModulus().ConvertToInt())).ConvertToInt());
    }
    return value.Times(factors);
}

RingPoly Automorphism(const RingPoly& value, uint32_t exponent) {
    const uint32_t order = value.GetCyclotomicOrder();
    if (!(exponent & 1) || exponent >= order) throw std::invalid_argument("Invalid automorphism exponent");
    auto coefficient = value;
    coefficient.SetFormat(COEFFICIENT);
    auto out = coefficient.AutomorphismTransform(exponent);
    out.SetFormat(value.GetFormat());
    return out;
}

uint32_t RotationExponent(int64_t steps, uint32_t n) {
    if (n < 2 || (n & (n - 1)) || n > std::numeric_limits<uint32_t>::max() / 2) {
        throw std::invalid_argument("Invalid rotation ring dimension");
    }
    const int64_t period = n / 2;
    uint64_t power = static_cast<uint64_t>((steps % period + period) % period);
    uint64_t base = 5, result = 1, modulus = uint64_t(n) * 2;
    while (power) {
        if (power & 1) result = result * base % modulus;
        base = base * base % modulus;
        power >>= 1;
    }
    return static_cast<uint32_t>(result);
}
}  // namespace mlwr
