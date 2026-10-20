#include "mlwr/profile.hpp"

#include <cmath>
#include <iomanip>
#include <ostream>
#include <set>
#include <stdexcept>

namespace mlwr {
void ValidateProfileOptions(uint32_t depth, uint32_t slots, uint32_t ring_dimension,
                            uint32_t scale_bits, uint32_t first_mod_bits, uint32_t security_bits, bool compact) {
    if (security_bits != 128 && security_bits != 192 && security_bits != 256)
        throw std::invalid_argument("security_bits must be 128, 192 or 256 (OpenFHE RLWE table only)");
    if (depth < 1 || depth > 10 || slots == 0 || (slots & (slots - 1)) || slots > 65536)
        throw std::invalid_argument("Supported profile: depth 1..10, power-of-two slots in 1..65536");
    if (ring_dimension && (ring_dimension < 1024 || ring_dimension > 131072 ||
                          (ring_dimension & (ring_dimension - 1))))
        throw std::invalid_argument("N must be 0 (automatic) or a power of two in 1024..131072");
    if (ring_dimension && slots > ring_dimension / 2)
        throw std::invalid_argument("slots must not exceed N/2");
    // Keep headroom above the engine's 2^40 minimum scale, and one bit
    // between the final scale and first modulus for this bounded workload.
    if (scale_bits < (compact ? 20u : 41u) || scale_bits > 59 || first_mod_bits <= scale_bits || first_mod_bits > 60)
        throw std::invalid_argument("scale_bits outside supported range; scale_bits < first_mod_bits <= 60 required");
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
        for (std::size_t i = 0; params && i < params->GetParams().size(); ++i) {
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
        << ",\"slots\":" << profile.slots << ",\"large_digits\":" << (profile.compact ? 0 : 1)
        << ",\"ckks_data_type\":\"COMPLEX\","
        << "\"scaling_technique\":\"" << crypto->GetScalingTechnique()
        << "\",\"rlwe_security_table\":\"" << crypto->GetStdLevel()
        << "\",\"secret_distribution\":\"" << crypto->GetSecretKeyDist()
        << "\",\"ciphertext_basis\":";
    basis(profile.ciphertext);
    out << ",\"auxiliary_basis\":";
    basis(profile.auxiliary);
    out << ",\"encoding_scales\":[";
    for (std::size_t i = 0; !profile.compact && i < profile.ciphertext->GetParams().size(); ++i) {
        if (i) out << ',';
        out << (i == 0 ? crypto->GetScalingFactorRealBig(0) : crypto->GetScalingFactorReal(i));
    }
    out << ']';
    if (profile.compact) out << ",\"construction_mode\":\"compact_pair_bv\",\"gadget_bits\":"
        << profile.gadget_bits << ",\"public_extra_bits\":" << profile.public_extra_bits
        << ",\"rotation_gadget_bits\":" << profile.rotation_gadget_bits
        << ",\"symmetric_relinearization\":" << (profile.symmetric_relinearization ? "true" : "false")
        << ",\"packed_public_key\":" << (profile.packed_public_key ? "true" : "false")
        << ",\"checked_public_modulus_bits\":" << profile.checked_public_bits
        << ",\"key_switch_technique\":\"gadget_small_P\"";
    out << '}';
}

RnsParams IndependentLargerBasis(const RnsParams& model, const RnsParams& exclude, uint32_t extra_bits, bool small_extra) {
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
    auto extra = small_extra ? lbcrypto::FirstPrime<lbcrypto::NativeInteger>(extra_bits - 1, order)
                             : lbcrypto::LastPrime<lbcrypto::NativeInteger>(extra_bits, order);
    while (used.count(extra.ConvertToInt())) extra = small_extra ? lbcrypto::NextPrime(extra, order)
                                                              : lbcrypto::PreviousPrime(extra, order);
    primes.push_back(extra.ConvertToInt());
    auto result = MakeRnsParams(model->GetRingDimension(), primes);
    if (result->GetModulus() <= model->GetModulus())
        throw std::runtime_error("Independent source basis must be larger than target");
    return result;
}

RnsParams PackedLargerBasis(const RnsParams& model,uint32_t extra_bits) {
    if(extra_bits<16 || extra_bits>40)throw std::invalid_argument("Packed public extra bits must be 16..40");
    const auto target=model->GetModulus()*(Integer(1)<<(extra_bits-1));
    const auto count=(target.GetMSB()+58)/59;
    const auto order=model->GetCyclotomicOrder();
    std::set<uint64_t> used;
    for(const auto& p:model->GetParams())used.insert(p->GetModulus().ConvertToInt());
    Integer product(1);std::vector<uint64_t> primes;
    auto large=lbcrypto::LastPrime<lbcrypto::NativeInteger>(59,order);
    for(uint32_t i=0;i<count;++i) {
        lbcrypto::NativeInteger candidate;
        if(i+1==count) {
            const auto needed=(target/product).ConvertToInt();
            candidate=lbcrypto::NextPrime(lbcrypto::NativeInteger(needed/order*order+1),order);
            while(used.count(candidate.ConvertToInt()))candidate=lbcrypto::NextPrime(candidate,order);
        } else {
            candidate=large;
            while(used.count(candidate.ConvertToInt()))candidate=lbcrypto::PreviousPrime(candidate,order);
            large=lbcrypto::PreviousPrime(candidate,order);
        }
        if(candidate.GetMSB()>60)throw std::invalid_argument("Packed public prime exceeds native 60-bit limit");
        primes.push_back(candidate.ConvertToInt());used.insert(candidate.ConvertToInt());
        product*=Integer(candidate.ConvertToInt());
    }
    if(product<=target)throw std::runtime_error("Packed public modulus did not exceed its exact target");
    return MakeRnsParams(model->GetRingDimension(),primes);
}

Profile CompactProfile(uint32_t depth, uint32_t slots, uint32_t n, uint32_t scale_bits,
                       uint32_t first_bits, uint32_t security_bits, uint32_t divisor_bits,
                       uint32_t gadget_bits, uint32_t public_extra_bits, uint32_t rotation_gadget_bits, double scale_log2,
                       bool packed_public_key) {
    ValidateProfileOptions(depth, slots, n, scale_bits, first_bits, security_bits, true);
    if(divisor_bits<16||divisor_bits>40||gadget_bits<4||gadget_bits>30||public_extra_bits<16||public_extra_bits>40||
       rotation_gadget_bits<4||rotation_gadget_bits>30)
        throw std::invalid_argument("Compact divisor/public-extra bits 16..40 and gadget bits 4..30 required");
    if (!n) throw std::invalid_argument("Compact mode requires an explicit N for auditable parameter planning");
    if(!std::isfinite(scale_log2) || (scale_log2 &&
       (scale_log2<20 || scale_log2>=59 || std::floor(scale_log2)!=scale_bits || std::ceil(scale_log2)>=first_bits)))
        throw std::invalid_argument("Invalid fractional compact prime target");
    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(depth); params.SetBatchSize(slots); params.SetRingDim(n);
    params.SetScalingModSize(scale_log2?static_cast<uint32_t>(std::ceil(scale_log2)):scale_bits); params.SetFirstModSize(first_bits);
    params.SetScalingTechnique(lbcrypto::FIXEDMANUAL); params.SetKeySwitchTechnique(lbcrypto::BV);
    params.SetDigitSize(gadget_bits); params.SetCKKSDataType(lbcrypto::COMPLEX);
    const auto security = security_bits == 128 ? lbcrypto::HEStd_128_classic :
        security_bits == 192 ? lbcrypto::HEStd_192_classic : lbcrypto::HEStd_256_classic;
    params.SetSecurityLevel(security);
    auto cc = lbcrypto::GenCryptoContext(params);
    auto crypto = std::dynamic_pointer_cast<lbcrypto::CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    auto base = crypto->GetElementParams();
    if(scale_log2) {
        // The compact engine uses the OpenFHE canonical encoder but owns its
        // exact RNS chain. Center nearby NTT primes around 2^scale_log2 rather
        // than rounding every requested modulus to a whole power of two.
        // Preserve the first modulus, distinct primes and exact primitive roots.
        const uint64_t order=2*n;
        const uint64_t center=static_cast<uint64_t>(std::exp2(scale_log2))/order*order+1;
        auto up=lbcrypto::NativeInteger(center),down=up;
        std::vector<uint64_t> primes{base->GetParams().front()->GetModulus().ConvertToInt()};
        std::set<uint64_t> used{primes.front()};
        for(uint32_t i=0;i<depth;++i) {
            auto& cursor=(i%2)?up:down;
            do {cursor=(i%2)?lbcrypto::NextPrime(cursor,order):lbcrypto::PreviousPrime(cursor,order);}
            while(used.count(cursor.ConvertToInt()));
            used.insert(cursor.ConvertToInt());primes.push_back(cursor.ConvertToInt());
        }
        base=MakeRnsParams(n,primes);
    }
    auto divisor = lbcrypto::FirstPrime<lbcrypto::NativeInteger>(divisor_bits - 1, 2 * n);
    for (;;) {
        bool used = false;
        for (const auto& q : base->GetParams()) used |= q->GetModulus() == divisor;
        if (!used) break;
        divisor = lbcrypto::NextPrime(divisor, 2 * n);
    }
    auto full = JoinBases(base, MakeRnsParams(n, {divisor.ConvertToInt()}));
    auto public_basis = packed_public_key ? PackedLargerBasis(full,public_extra_bits) :
                                           IndependentLargerBasis(full, nullptr, public_extra_bits, true);
    // The public key uses T > Q, so check T as well as Q. No HEStd_NotSet
    // context is created, and no security test is waived to fit a requested N.
    auto auxiliary_prime = lbcrypto::LastPrime<lbcrypto::NativeInteger>(public_extra_bits, 2*n);
    for (;;) {
        bool used=false;for(const auto& q:full->GetParams())used|=q->GetModulus()==auxiliary_prime;
        if(!used)break;auxiliary_prime=lbcrypto::PreviousPrime(auxiliary_prime,2*n);
    }
    auto auxiliary=MakeRnsParams(n,{auxiliary_prime.ConvertToInt()});
    const auto bits = std::max(public_basis->GetModulus().GetMSB(),
        (full->GetModulus()*auxiliary->GetModulus()).GetMSB());
    const auto required = lbcrypto::StdLatticeParm::FindRingDim(lbcrypto::HEStd_ternary, security, bits);
    if (required > n) throw std::invalid_argument("The specified ring dimension (" + std::to_string(n) +
        ") does not comply with HE standards recommendation (" + std::to_string(required) +
        "). Compact check includes the public-key modulus T (" + std::to_string(bits) + " bits).");
    Profile result{cc, full, auxiliary, depth, slots};
    result.compact = true; result.gadget_bits = gadget_bits;
    result.public_extra_bits = public_extra_bits; result.checked_public_bits = bits;
    result.rotation_gadget_bits = rotation_gadget_bits;
    result.packed_public_key = packed_public_key;
    return result;
}
}  // namespace mlwr
