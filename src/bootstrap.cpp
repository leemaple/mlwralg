#include "mlwr/bootstrap.hpp"

#include <cmath>
#include <chrono>
#include <iomanip>
#include <ostream>
#include <stdexcept>

#ifdef MLWR_P03_PATCH
namespace lbcrypto { void MLWRConfigureP03Small(const CryptoContext<DCRTPoly>&,bool); }
#endif

namespace mlwr {
namespace {
lbcrypto::SecurityLevel Security(uint32_t bits) {
    if (bits == 128) return lbcrypto::HEStd_128_classic;
    if (bits == 192) return lbcrypto::HEStd_192_classic;
    if (bits == 256) return lbcrypto::HEStd_256_classic;
    throw std::invalid_argument("security_bits must be 128, 192 or 256");
}
RingPoly Zero(const RnsParams& p) { return RingPoly(p, EVALUATION, true); }
using Clock = std::chrono::steady_clock;
double Elapsed(Clock::time_point start) {
    return std::chrono::duration<double,std::milli>(Clock::now()-start).count();
}
void ConfigureSparse(const BootstrapProfile& p) {
#ifdef MLWR_P03_PATCH
    lbcrypto::MLWRConfigureP03Small(p.module.encoder,p.requested.paper_sparse);
#else
    if(p.requested.paper_sparse)throw std::invalid_argument("P03 path requires the pinned patched OpenFHE build");
#endif
}
}

BootstrapProfile MakeBootstrapProfile(const BootstrapOptions& o) {
    if (!o.n || (o.n & (o.n-1)) || o.n < 4096 || o.n > 131072 ||
        !o.slots || (o.slots & (o.slots-1)) || o.slots > o.n/2 ||
        o.scale_bits < 41 || o.scale_bits > 59 || o.first_bits <= o.scale_bits ||
        o.first_bits > 60 || !o.usable_levels || o.usable_levels > 20 ||
        !o.cts_levels || !o.stc_levels || o.cts_levels > 4 || o.stc_levels > 4 ||
        !o.large_digits || o.large_digits > 8 || o.correction_factor > 20 ||
        (o.module_gadget_bits && (o.module_gadget_bits<4 || o.module_gadget_bits>30)))
        throw std::invalid_argument("Unsupported bootstrap profile options");
    const auto security = Security(o.security_bits);
    if(o.project_repeated && !o.flexible_scaling)
        throw std::invalid_argument("Repeated-slot projection requires flexible scaling for the next refresh");
    if(o.paper_sparse && (o.cts_levels!=1 || o.stc_levels!=1 || uint64_t(8)*o.slots*o.slots>o.n))
        throw std::invalid_argument("P03 small regime requires budgets 1/1 and 8*slots^2 <= N");
#ifndef MLWR_P03_PATCH
    if(o.paper_sparse)throw std::invalid_argument("P03 path requires the pinned patched OpenFHE build");
#endif
    const std::vector<uint32_t> budget{o.cts_levels, o.stc_levels};
    const auto boot_depth = lbcrypto::FHECKKSRNS::GetBootstrapDepth(budget, lbcrypto::UNIFORM_TERNARY);
    const auto depth = boot_depth + o.usable_levels;
    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> params;
    params.SetRingDim(o.n); params.SetBatchSize(o.slots);
    params.SetSecretKeyDist(lbcrypto::UNIFORM_TERNARY); params.SetSecurityLevel(security);
    params.SetMultiplicativeDepth(depth); params.SetScalingModSize(o.scale_bits);
    params.SetFirstModSize(o.first_bits);
    params.SetScalingTechnique(o.flexible_scaling ? lbcrypto::FLEXIBLEAUTO : lbcrypto::FIXEDMANUAL);
    params.SetKeySwitchTechnique(lbcrypto::HYBRID); params.SetNumLargeDigits(o.large_digits);
    params.SetCKKSDataType(lbcrypto::COMPLEX);
    auto cc = lbcrypto::GenCryptoContext(params);
    auto crypto = std::dynamic_pointer_cast<lbcrypto::CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    // The module's existing ungadgeted relinearization needs its own P > Q.
    // Count that QP, native HYBRID QP, and the actual module public-key modulus T.
    // No security-disabled context is created to fit a requested small N.
    auto q = crypto->GetElementParams();
    RnsParams p;
    if(o.module_gadget_bits) {
        auto prime=lbcrypto::LastPrime<lbcrypto::NativeInteger>(60,2*o.n);
        const auto used=[&](const lbcrypto::NativeInteger& value) {
            for(const auto& tower:q->GetParams())if(tower->GetModulus()==value)return true;
            return false;
        };
        while(used(prime))prime=lbcrypto::PreviousPrime(prime,2*o.n);
        p=MakeRnsParams(o.n,{prime.ConvertToInt()});
    } else p = IndependentLargerBasis(q, crypto->GetParamsP());
    auto t = IndependentLargerBasis(q, p);
    const auto bits = std::max({(q->GetModulus()*p->GetModulus()).GetMSB(),
        (q->GetModulus()*crypto->GetParamsP()->GetModulus()).GetMSB(), t->GetModulus().GetMSB()});
    const auto required = lbcrypto::StdLatticeParm::FindRingDim(lbcrypto::HEStd_ternary, security, bits);
    if (required > o.n)
        throw std::invalid_argument("Bootstrap full public-modulus budget requires N=" +
            std::to_string(required) + " for " + std::to_string(bits) +
            " bits; requested N=" + std::to_string(o.n));
    for (auto feature : {lbcrypto::PKE, lbcrypto::KEYSWITCH, lbcrypto::LEVELEDSHE,
                         lbcrypto::ADVANCEDSHE, lbcrypto::FHE}) cc->Enable(feature);
    Profile module{cc,q,p,depth,o.slots};module.standard_gadget_bits=o.module_gadget_bits;
    module.checked_public_bits=bits;
    return {module, o, boot_depth, bits, required};
}

void WriteBootstrapProfile(std::ostream& out, const BootstrapProfile& p) {
    auto crypto = std::dynamic_pointer_cast<lbcrypto::CryptoParametersCKKSRNS>(p.module.encoder->GetCryptoParameters());
    out << "{\"mode\":\"module_rlwe_bootstrap_bridge\",\"N\":" << p.requested.n
        << ",\"slots\":" << p.requested.slots << ",\"security_bits\":" << p.requested.security_bits
        << ",\"security_scope\":\"RLWE_table_not_MLWR_proof\",\"secret_distribution\":\"UNIFORM_TERNARY\""
        << ",\"scale_bits\":" << p.requested.scale_bits << ",\"first_mod_bits\":" << p.requested.first_bits
        << ",\"scaling_technique\":\"" << (p.requested.flexible_scaling ? "FLEXIBLEAUTO" : "FIXEDMANUAL") << '"'
        << ",\"cts_levels\":" << p.requested.cts_levels << ",\"stc_levels\":" << p.requested.stc_levels
        << ",\"large_digits\":" << p.requested.large_digits << ",\"bootstrap_depth\":" << p.bootstrap_depth
        << ",\"requested_usable_levels\":" << p.requested.usable_levels << ",\"total_depth\":" << p.module.depth
        << ",\"checked_public_bits\":" << p.public_bits << ",\"required_N\":" << p.required_n
        << ",\"Q_bits\":" << p.module.ciphertext->GetModulus().GetMSB()
        << ",\"module_P_bits\":" << p.module.auxiliary->GetModulus().GetMSB()
        << ",\"module_gadget_bits\":" << p.requested.module_gadget_bits
        << ",\"transform\":\"" << (p.requested.paper_sparse?"P03_small_repeated":"OpenFHE_native") << '"'
        << ",\"project_repeated\":" << (p.requested.project_repeated?"true":"false")
        << ",\"native_P_bits\":" << crypto->GetParamsP()->GetModulus().GetMSB()
        << ",\"openfhe_version\":\"1.6.1\",\"Q_primes\":[";
    bool first = true;
    for (const auto& q : p.module.ciphertext->GetParams()) {
        if (!first) out << ',';
        first = false;
        out << "{\"prime\":\"" << q->GetModulus() << "\",\"root\":\"" << q->GetRootOfUnity() << "\"}";
    }
    out << ']';
    const auto write_basis=[&](const char* name,const RnsParams& basis) {
        out << ",\"" << name << "\":[";
        bool first=true;
        for(const auto& q:basis->GetParams()) {
            if(!first)out << ',';
            first=false;
            out << "{\"prime\":\"" << q->GetModulus() << "\",\"root\":\"" << q->GetRootOfUnity() << "\"}";
        }
        out << ']';
    };
    write_basis("module_P_primes",p.module.auxiliary);
    write_basis("native_P_primes",crypto->GetParamsP());
    write_basis("public_T_primes",IndependentLargerBasis(p.module.ciphertext,p.module.auxiliary));
    out << ",\"correction_factor_requested\":" << p.requested.correction_factor
        << ",\"openfhe_commit\":\"b59e1f291965f14fbee5172cd83a20f5b856204f\"";
#ifdef MLWR_P03_PATCH
    out << ",\"port_helper_sha256\":\"" << MLWR_PORT_HELPER_SHA
        << "\",\"patched_fhe_sha256\":\"" << MLWR_PORT_FHE_SHA << '"';
#endif
    out << '}';
}

BootstrapBridge::BootstrapBridge(const ResearchScheme& scheme, const BootstrapProfile& profile)
    : scheme_(scheme), profile_(profile) {
    if (scheme.profile().encoder != profile.module.encoder ||
        !SameBasis(scheme.profile().ciphertext, profile.module.ciphertext) ||
        !SameBasis(scheme.profile().auxiliary, profile.module.auxiliary))
        throw std::invalid_argument("Bootstrap scheme/profile mismatch");
}

BootstrapKey BootstrapBridge::KeyGen(const SecretKey& secret,std::map<std::string,double>* timings) const {
    ConfigureSparse(profile_);
    if (!secret.context || !secret.tag || secret.s.size() != scheme_.k())
        throw std::invalid_argument("Bootstrap module key shape mismatch");
    // Phase performs the scheme's context/key validation without decrypting a message.
    Ciphertext zero{Row(scheme_.k()+1, Zero(profile_.module.ciphertext)),
        std::ldexp(1.0, profile_.requested.scale_bits), 1, 0, secret.context, secret.tag};
    (void)scheme_.Phase(secret, zero);
    auto cc = profile_.module.encoder;
    std::vector<lbcrypto::PrivateKey<RingPoly>> private_parts;
    for (const auto& s : secret.s) {
        auto key = std::make_shared<lbcrypto::PrivateKeyImpl<RingPoly>>(cc);
        key->SetPrivateElement(Zero(profile_.module.ciphertext)-s);
        private_parts.push_back(std::move(key));
    }
    BootstrapKey result;
    result.context = secret.context; result.key_tag = secret.tag; result.k = scheme_.k();
    result.native_tag = private_parts.front()->GetKeyTag();
    for (const auto& s : private_parts) result.source_tags.push_back(s->GetKeyTag());
    auto start=Clock::now();
    for (uint32_t j=1; j<scheme_.k(); ++j)
        result.folding.push_back(cc->KeySwitchGen(private_parts[j], private_parts.front()));
    result.bound_folding_=result.folding;
    if(timings)(*timings)["fold_keygen_ms"]=Elapsed(start);
    start=Clock::now();
    cc->EvalBootstrapSetup({profile_.requested.cts_levels, profile_.requested.stc_levels},
                          {0,0}, profile_.requested.slots, profile_.requested.correction_factor);
    if(timings)(*timings)["bootstrap_setup_ms"]=Elapsed(start);
    start=Clock::now();
    cc->EvalMultKeyGen(private_parts.front());
    if(timings)(*timings)["native_mult_keygen_ms"]=Elapsed(start);
    start=Clock::now();
    cc->EvalBootstrapKeyGen(private_parts.front(), profile_.requested.slots);
    if(timings)(*timings)["native_bootstrap_keygen_ms"]=Elapsed(start);
    return result;
}

void BootstrapBridge::ValidateKey(const BootstrapKey& key) const {
    if (!key.context || key.context != scheme_.context_id() || !key.key_tag ||
        key.k != scheme_.k() || key.folding.size() != key.k-1 ||
        key.folding != key.bound_folding_ ||
        key.source_tags.size() != key.k || key.native_tag.empty())
        throw std::invalid_argument("Bootstrap evaluation key context/shape mismatch");
    if(key.source_tags.front()!=key.native_tag)
        throw std::invalid_argument("Bootstrap native/source tag mismatch");
    for(const auto& tag:key.source_tags)
        if(tag.empty())throw std::invalid_argument("Empty bootstrap source tag");
    auto crypto=std::dynamic_pointer_cast<lbcrypto::CryptoParametersCKKSRNS>(profile_.module.encoder->GetCryptoParameters());
    for(const auto& folding:key.folding) {
        if(!folding || folding->GetCryptoContext()!=profile_.module.encoder ||
            folding->GetKeyTag()!=key.native_tag)
            throw std::invalid_argument("Invalid bootstrap folding key");
        if(folding->GetAVector().size()!=crypto->GetNumPartQ() ||
           folding->GetBVector().size()!=crypto->GetNumPartQ())
            throw std::invalid_argument("Bootstrap folding key digit shape mismatch");
        for(const auto* rows:{&folding->GetAVector(),&folding->GetBVector()})
            for(const auto& part:*rows)
                if(part.GetFormat()!=EVALUATION || !SameBasis(part.GetParams(),crypto->GetParamsQP()))
                    throw std::invalid_argument("Bootstrap folding key exact basis mismatch");
    }
}

void BootstrapBridge::Validate(const Ciphertext& x, const BootstrapKey& key) const {
    ValidateKey(key);
    if (x.context != key.context || x.key_tag != key.key_tag || x.c.size() != key.k+1 ||
        !std::isfinite(x.scale) || x.scale < 0x1p40 || !std::isfinite(x.bound) || x.bound <= 0)
        throw std::invalid_argument("Bootstrap bridge ciphertext context/key/shape/scale mismatch");
    const auto basis = scheme_.basis(x.level);
    for (const auto& c : x.c)
        if (c.GetFormat()!=EVALUATION || !SameBasis(c.GetParams(), basis))
            throw std::invalid_argument("Bootstrap bridge exact basis mismatch");
    if (x.scale*(x.bound+1) >= basis->GetModulus().ConvertToDouble()/2)
        throw std::invalid_argument("Bootstrap bridge public message budget exceeded");
}

lbcrypto::Ciphertext<RingPoly> BootstrapBridge::Fold(const Ciphertext& x, const BootstrapKey& key) const {
    Validate(x,key);
    auto cc = profile_.module.encoder;
    auto make = [&](const RingPoly& a, const RingPoly& b, const std::string& tag) {
        auto c = std::make_shared<lbcrypto::CiphertextImpl<RingPoly>>(cc,tag,lbcrypto::CKKS_PACKED_ENCODING);
        c->SetElements({a,b}); c->SetLevel(x.level); c->SetNoiseScaleDeg(1);
        c->SetScalingFactor(x.scale); c->SetSlots(profile_.requested.slots);
        return c;
    };
    auto result = make(x.c[0],x.c[1],key.native_tag);
    for (uint32_t j=1; j<key.k; ++j) {
        // Import produces a collapsed row. Do not key-switch zero components.
        if(x.c[j+1]==Zero(scheme_.basis(x.level)))continue;
        auto term = make(Zero(scheme_.basis(x.level)),x.c[j+1],key.source_tags[j]);
        auto switched = cc->KeySwitch(term,key.folding[j-1]);
        auto elements = result->GetElements();
        for (uint32_t i=0;i<2;++i) elements[i] += switched->GetElements()[i];
        result->SetElements(std::move(elements));
    }
    return result;
}

Ciphertext BootstrapBridge::Import(const lbcrypto::Ciphertext<RingPoly>& input,
                                   const BootstrapKey& key, double public_bound) const {
    ValidateKey(key);
    if (!input || input->GetCryptoContext()!=profile_.module.encoder ||
        input->GetKeyTag()!=key.native_tag || input->GetElements().size()!=2 ||
        input->GetSlots()!=profile_.requested.slots || input->GetNoiseScaleDeg()!=1 ||
        input->GetLevel()>profile_.module.depth)
        throw std::invalid_argument("Bootstrap native output context/key/metadata mismatch");
    const auto level = static_cast<uint32_t>(input->GetLevel());
    Row row(key.k+1,Zero(scheme_.basis(level)));
    row[0]=input->GetElements()[0]; row[1]=input->GetElements()[1];
    Ciphertext result{std::move(row),input->GetScalingFactor(),public_bound,level,key.context,key.key_tag};
    Validate(result,key);
    return result;
}

Ciphertext BootstrapBridge::Refresh(const Ciphertext& x, const BootstrapKey& key,
                                    uint32_t iterations, uint32_t correction_precision,
                                    std::map<std::string,double>* timings) const {
    if ((iterations!=1 && iterations!=2) || (iterations==2 && (correction_precision<1 || correction_precision>30)))
        throw std::invalid_argument("Bootstrap iterations 1/2; correction precision 1..30 for iteration 2");
    auto start=Clock::now();
    auto input = Fold(x,key);
    if(timings)(*timings)["fold_ms"]=Elapsed(start);
    ConfigureSparse(profile_);
    start=Clock::now();
    auto refreshed = profile_.module.encoder->EvalBootstrap(input,iterations,correction_precision);
    if(timings)(*timings)["native_bootstrap_ms"]=Elapsed(start);
    start=Clock::now();
    if (refreshed->GetNoiseScaleDeg()>1)
        profile_.module.encoder->GetScheme()->ModReduceInternalInPlace(refreshed,refreshed->GetNoiseScaleDeg()-1);
    if(timings)(*timings)["normalize_ms"]=Elapsed(start);
    start=Clock::now();
    if(profile_.requested.project_repeated)refreshed=ProjectRepeated(refreshed);
    if(timings)(*timings)["project_repeated_ms"]=Elapsed(start);
    start=Clock::now();
    auto result = Import(refreshed,key,x.bound);
    if(timings)(*timings)["import_ms"]=Elapsed(start);
    if (result.level >= x.level)
        throw std::runtime_error("Bootstrap did not restore any usable modulus levels");
    return result;
}

Ciphertext BootstrapBridge::HybridMultiply(const Ciphertext& a,
        const lbcrypto::Ciphertext<RingPoly>& factor,const BootstrapKey& key,double factor_bound,
        std::map<std::string,double>* timings) const {
    auto start=Clock::now();
    // Import checks the external native factor's tag, basis, degree and bound.
    (void)Import(factor,key,factor_bound);
    auto input=Fold(a,key);
    if(factor->GetLevel()>input->GetLevel())
        throw std::invalid_argument("Encrypted factor has fewer remaining levels than the input");
    // FLEXIBLEAUTO's unequal-level adjustment assumes its scheduled scale at
    // both levels. A public trace has an actual scale multiplied by the number
    // of copies. Project the factor to the exact same basis without changing
    // its physical scale; multiplication then uses the true product of scales.
    auto aligned=factor->Clone();
    auto elements=aligned->GetElements();
    for(auto& part:elements)part=SelectBasis(part,scheme_.basis(a.level));
    aligned->SetElements(std::move(elements));aligned->SetLevel(a.level);
    if(timings)(*timings)["fold_validate_ms"]=Elapsed(start);
    auto cc=profile_.module.encoder;
    start=Clock::now();
    auto tensor=cc->EvalMultNoRelin(input,aligned);
    if(timings)(*timings)["tensor_align_ms"]=Elapsed(start);
    start=Clock::now();
    auto result=cc->Relinearize(tensor);
    if(timings)(*timings)["relinearize_ms"]=Elapsed(start);
    start=Clock::now();
    if(result->GetNoiseScaleDeg()>1)
        cc->GetScheme()->ModReduceInternalInPlace(result,result->GetNoiseScaleDeg()-1);
    if(timings)(*timings)["rescale_ms"]=Elapsed(start);
    start=Clock::now();
    auto output=Import(result,key,a.bound*factor_bound);
    if(timings)(*timings)["import_ms"]=Elapsed(start);
    return output;
}
lbcrypto::Ciphertext<RingPoly> BootstrapBridge::ProjectRepeated(const lbcrypto::Ciphertext<RingPoly>& input) const {
    if(!input || input->GetCryptoContext()!=profile_.module.encoder ||
       input->GetElements().size()!=2 || input->GetSlots()!=profile_.requested.slots || input->GetNoiseScaleDeg()!=1 ||
       !std::isfinite(input->GetScalingFactor()) || input->GetScalingFactor()<=0)
        throw std::invalid_argument("Repeated-slot projection context/metadata mismatch");
    if(input->GetLevel()>profile_.module.depth)
        throw std::invalid_argument("Repeated-slot projection level out of range");
    for(const auto& part:input->GetElements())
        if(part.GetFormat()!=EVALUATION || !SameBasis(part.GetParams(),scheme_.basis(input->GetLevel())))
            throw std::invalid_argument("Repeated-slot projection exact basis mismatch");
    auto output=input->Clone();
    const auto copies=profile_.requested.n/(2*profile_.requested.slots);
    if(copies>1) {
        // Public trace onto the repeated-slot subring. The ciphertext is
        // physically summed over all copies. Recording scale*copies interprets
        // that sum as their average; merely editing the scale is not this map.
        lbcrypto::FHECKKSRNS::EvalPartialSumInPlace(output,profile_.requested.slots,copies);
        output->SetScalingFactor(input->GetScalingFactor()*copies);
        // Native bootstrap assumes its scheduled scale, even with FLEXIBLEAUTO.
        // Restore it by an actual integer multiplication and one real rescale.
        // If D is the trace scale, choose A≈q*S_next/D. Then D*A/q is near S_next.
        // Record the actual D*A/q, never fix the value by changing metadata alone.
        auto crypto=std::dynamic_pointer_cast<lbcrypto::CryptoParametersCKKSRNS>(
            profile_.module.encoder->GetCryptoParameters());
        const auto& towers=output->GetElements().front().GetParams()->GetParams();
        if(towers.size()<2)throw std::invalid_argument("Trace normalization needs one real rescale level");
        const double q=towers.back()->GetModulus().ConvertToDouble();
        const double target=crypto->GetScalingFactorReal(output->GetLevel()+1);
        const double factor=q*target/output->GetScalingFactor();
        if(!std::isfinite(factor) || factor<1 || factor>=0x1p60)
            throw std::invalid_argument("Trace normalization integer is outside supported range");
        const auto integer=static_cast<uint64_t>(std::llround(factor));
        auto elements=output->GetElements();
        for(auto& part:elements)part=MultiplyInteger(part,Integer(integer));
        output->SetElements(std::move(elements));
        output->SetScalingFactor(output->GetScalingFactor()*integer);
        output->SetNoiseScaleDeg(2);
        profile_.module.encoder->GetScheme()->ModReduceInternalInPlace(output,1);
        if(std::abs(output->GetScalingFactor()/target-1)>1e-9)
            throw std::runtime_error("Trace normalization did not reach the native scale contract");
    }
    return output;
}
}  // namespace mlwr
