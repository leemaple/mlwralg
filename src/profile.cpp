#include "mlwr/profile.hpp"

#include <iomanip>
#include <ostream>
#include <set>
#include <stdexcept>

namespace mlwr {
void ValidateProfileOptions(uint32_t depth, uint32_t slots, uint32_t ring_dimension,
                            uint32_t scale_bits, uint32_t first_mod_bits, uint32_t security_bits) {
    if (security_bits != 128 && security_bits != 192 && security_bits != 256)
        throw std::invalid_argument("security_bits must be 128, 192 or 256 (OpenFHE RLWE table only)");
    if (depth < 1 || depth > 6 || slots == 0 || (slots & (slots - 1)) || slots > 65536)
        throw std::invalid_argument("Supported profile: depth 1..6, power-of-two slots in 1..65536");
    if (ring_dimension && (ring_dimension < 1024 || ring_dimension > 131072 ||
                          (ring_dimension & (ring_dimension - 1))))
        throw std::invalid_argument("N must be 0 (automatic) or a power of two in 1024..131072");
    if (ring_dimension && slots > ring_dimension / 2)
        throw std::invalid_argument("slots must not exceed N/2");
    // Keep headroom above the engine's 2^40 minimum scale, and one bit
    // between the final scale and first modulus for this bounded workload.
    if (scale_bits < 41 || scale_bits > 59 || first_mod_bits <= scale_bits || first_mod_bits > 60)
        throw std::invalid_argument("scale_bits must be 41..59; scale_bits < first_mod_bits <= 60");
}

Profile OpenFheProfile(uint32_t depth, uint32_t slots, uint32_t ring_dimension,
                       uint32_t scale_bits, uint32_t first_mod_bits, uint32_t security_bits) {
    ValidateProfileOptions(depth, slots, ring_dimension, scale_bits, first_mod_bits, security_bits);
    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(depth);
    params.SetBatchSize(slots);
    params.SetRingDim(ring_dimension);
    params.SetScalingModSize(scale_bits);
    params.SetFirstModSize(first_mod_bits);
    params.SetSecurityLevel(security_bits == 128 ? lbcrypto::HEStd_128_classic :
                            security_bits == 192 ? lbcrypto::HEStd_192_classic : lbcrypto::HEStd_256_classic);
    params.SetCKKSDataType(lbcrypto::COMPLEX);
    // The disclosure has a single (non-gadget) switching product. The default
    // multi-digit HYBRID auxiliary modulus is too small for that operation.
    // Apply this explicit OpenFHE option to BOTH algorithms in the comparison.
    params.SetNumLargeDigits(1);
    auto cc = lbcrypto::GenCryptoContext(params);
    auto crypto = std::dynamic_pointer_cast<lbcrypto::CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    if (slots > cc->GetRingDimension() / 2 || crypto->GetSecretKeyDist() != lbcrypto::UNIFORM_TERNARY)
        throw std::runtime_error("Unsupported OpenFHE packing or secret distribution");
    Profile profile{cc, crypto->GetElementParams(), crypto->GetParamsP(), depth, slots};
    if (profile.auxiliary->GetModulus() <= profile.ciphertext->GetModulus())
        throw std::runtime_error("One-digit switching requires auxiliary modulus > ciphertext modulus");
    return profile;
}

void WriteProfileJson(std::ostream& out, const Profile& profile) {
    const auto crypto = std::dynamic_pointer_cast<lbcrypto::CryptoParametersCKKSRNS>(
        profile.encoder->GetCryptoParameters());
    auto basis = [&](const RnsParams& params) {
        out << '[';
        for (std::size_t i = 0; i < params->GetParams().size(); ++i) {
            if (i) out << ',';
            out << "{\"prime\":\"" << params->GetParams()[i]->GetModulus()
                << "\",\"root\":\"" << params->GetParams()[i]->GetRootOfUnity() << "\"}";
        }
        out << ']';
    };
    out << std::setprecision(17)
        << "{\"openfhe_version\":\"1.6.1\","
        << "\"openfhe_commit\":\"b59e1f291965f14fbee5172cd83a20f5b856204f\","
        << "\"native_bits\":" << NATIVEINT << ",\"ring_dimension\":"
        << profile.ciphertext->GetRingDimension() << ",\"depth\":" << profile.depth
        << ",\"slots\":" << profile.slots << ",\"large_digits\":1,\"ckks_data_type\":\"COMPLEX\","
        << "\"scaling_technique\":\"" << crypto->GetScalingTechnique()
        << "\",\"rlwe_security_table\":\"" << crypto->GetStdLevel()
        << "\",\"secret_distribution\":\"" << crypto->GetSecretKeyDist()
        << "\",\"ciphertext_basis\":";
    basis(profile.ciphertext);
    out << ",\"auxiliary_basis\":";
    basis(profile.auxiliary);
    out << ",\"encoding_scales\":[";
    for (std::size_t i = 0; i < profile.ciphertext->GetParams().size(); ++i) {
        if (i) out << ',';
        out << (i == 0 ? crypto->GetScalingFactorRealBig(0) : crypto->GetScalingFactorReal(i));
    }
    out << "]}";
}

RnsParams IndependentLargerBasis(const RnsParams& model, const RnsParams& exclude) {
    std::set<uint64_t> used;
    for (const auto& p : model->GetParams()) used.insert(p->GetModulus().ConvertToInt());
    if (exclude)
        for (const auto& p : exclude->GetParams()) used.insert(p->GetModulus().ConvertToInt());
    const auto order = model->GetCyclotomicOrder();
    std::vector<uint64_t> primes;
    for (const auto& p : model->GetParams()) {
        // The short FLEXIBLEAUTOEXT tower can be near the smallest NTT prime;
        // searching downward can exhaust that range. Large towers search down
        // to remain strictly below the 60-bit native multiplication limit.
        const bool down = p->GetModulus().GetMSB() >= 59;
        auto next = [&](const lbcrypto::NativeInteger& q) {
            return down ? lbcrypto::PreviousPrime(q, order) : lbcrypto::NextPrime(q, order);
        };
        auto candidate = next(p->GetModulus());
        while (used.count(candidate.ConvertToInt())) candidate = next(candidate);
        used.insert(candidate.ConvertToInt());
        primes.push_back(candidate.ConvertToInt());
    }
    auto extra = lbcrypto::LastPrime<lbcrypto::NativeInteger>(30, order);
    while (used.count(extra.ConvertToInt())) extra = lbcrypto::PreviousPrime(extra, order);
    primes.push_back(extra.ConvertToInt());
    auto result = MakeRnsParams(model->GetRingDimension(), primes);
    if (result->GetModulus() <= model->GetModulus())
        throw std::runtime_error("Independent source basis must be larger than target");
    return result;
}
}  // namespace mlwr
