#include "mlwr/profile.hpp"

#include <iomanip>
#include <ostream>
#include <set>
#include <stdexcept>

namespace mlwr {
Profile OpenFheProfile(uint32_t depth, uint32_t slots) {
    if (depth < 1 || depth > 6 || slots == 0 || (slots & (slots - 1)))
        throw std::invalid_argument("Supported profile: depth 1..6, power-of-two slots");
    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(depth);
    params.SetBatchSize(slots);
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
