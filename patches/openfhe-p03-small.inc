// Independent implementation of the small repeated-slot regime of Algorithms
// 2 and 3 in ePrint 2026/1023. The mathematical masks were cross-checked against
// xiaopeng-stu/SlotToCoeff-and-CoeffToSlot at abec1a68cc110a0afdb54fa2fed412a7b381a8e6.
// This file is included inside namespace lbcrypto in the pinned OpenFHE source.
// It preserves OpenFHE 1.6.1's own EvalMod polynomial, overflow normalization,
// key distribution and security checks. It does not implement LCR or OverModRaise.

namespace {
// Retain the configured context so an allocator cannot recycle a raw pointer
// while its cached plaintext masks still belong to the previous context.
thread_local CryptoContext<DCRTPoly> mlwrP03Context;
thread_local std::map<std::tuple<uint32_t, uint32_t, bool, double>, Plaintext> mlwrP03Masks;

bool MLWRP03Active(const CryptoContext<DCRTPoly>& cc) {
    return mlwrP03Context == cc;
}

void MLWRP03Check(uint32_t N, uint32_t slots) {
    if (!slots || (slots & (slots-1)) || uint64_t(8)*slots*slots > N)
        OPENFHE_THROW("P03 small regime requires power-of-two slots and 8*slots^2 <= N.");
}

std::vector<int32_t> MLWRP03Rotations(uint32_t N,std::vector<int32_t> result) {
    // Retain native radix-4 PartialSum keys as well as our binary block sums.
    for(uint32_t s=1;s<N/2;s*=2)result.push_back(static_cast<int32_t>(s));
    std::sort(result.begin(),result.end());
    result.erase(std::unique(result.begin(),result.end()),result.end());
    return result;
}

Ciphertext<DCRTPoly> MLWRP03Mask(ConstCiphertext<DCRTPoly> input, uint32_t slots,
                                bool inverse, double alpha) {
    const auto cc=input->GetCryptoContext();
    const uint32_t N=cc->GetRingDimension(), full=N/2, block=N/(4*slots);
    MLWRP03Check(N,slots);
    const auto key=std::make_tuple(slots,static_cast<uint32_t>(input->GetLevel()),inverse,alpha);
    auto found=mlwrP03Masks.find(key);
    if(found==mlwrP03Masks.end()) {
        std::vector<uint32_t> exponents(slots);
        uint32_t value=1;
        for(auto& x:exponents){x=value;value=uint64_t(value)*5%(4*slots);}
        std::vector<std::complex<double>> mask(full);
        for(uint32_t pos=0;pos<full;++pos) {
            if(inverse && pos%block>=block/2)continue;
            const uint32_t coefficient=pos/block;
            const uint32_t exponent=uint64_t(coefficient)*exponents[pos%slots]%(4*slots);
            const double phase=(inverse?1.:-1.)*2*std::acos(-1.)*exponent/(4*slots);
            mask[pos]=std::polar(alpha,phase);
        }
        auto encoded=FHECKKSRNS::MakeAuxPlaintext(*cc,input->GetElements()[0].GetParams(),
                                                mask,1,input->GetLevel(),full);
        found=mlwrP03Masks.emplace(key,std::move(encoded)).first;
    }
    auto result=FHECKKSRNS::EvalMultExt(input,found->second);
    result->SetSlots(full);
    return result;
}

Ciphertext<DCRTPoly> MLWRP03CtS(ConstCiphertext<DCRTPoly> input,uint32_t slots,double alpha) {
    auto result=MLWRP03Mask(input,slots,false,alpha);
    const auto cc=input->GetCryptoContext();
    for(uint32_t step=1;step<slots;step*=2)
        cc->EvalAddInPlaceNoCheck(result,cc->EvalRotate(result,step));
    // Conjugation and the following scale reduction remain in EvalBootstrap.
    // Scalar arithmetic in EvalMod uses the native sparse-slot metadata.
    result->SetSlots(slots);
    return result;
}

Ciphertext<DCRTPoly> MLWRP03StC(ConstCiphertext<DCRTPoly> input,uint32_t slots,double alpha) {
    auto result=MLWRP03Mask(input,slots,true,alpha);
    const auto cc=input->GetCryptoContext();
    const uint32_t N=cc->GetRingDimension(),block=N/(4*slots);
    for(uint32_t count=1;count<2*slots;count*=2)
        cc->EvalAddInPlaceNoCheck(result,cc->EvalRotate(result,count*block));
    cc->EvalAddInPlaceNoCheck(result,cc->EvalRotate(result,N/(8*slots)));
    result->SetSlots(slots);
    return result;
}
} // namespace

void MLWRConfigureP03Small(const CryptoContext<DCRTPoly>& cc,bool enabled) {
    const auto next=enabled?cc:CryptoContext<DCRTPoly>{};
    if(mlwrP03Context!=next)mlwrP03Masks.clear();
    mlwrP03Context=next;
}
