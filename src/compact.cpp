#include "mlwr/compact.hpp"
#include "mlwr/gadget.hpp"
#include "math/dftransform.h"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <stdexcept>

namespace mlwr {
namespace {
std::atomic<uint64_t> compact_id{uint64_t{1} << 48};
RingPoly Zero(const RnsParams& p) { return RingPoly(p, EVALUATION, true); }
RingPoly Uniform(const RnsParams& p) { RingPoly::DugType g; return RingPoly(g,p,EVALUATION); }
RingPoly Ternary(const RnsParams& p) { RingPoly::TugType g; return RingPoly(g,p,EVALUATION); }
void Polynomial(const RingPoly& p, const RnsParams& expected) {
    if (p.GetFormat()!=EVALUATION || !SameBasis(p.GetParams(),expected))
        throw std::invalid_argument("Compact polynomial basis/format mismatch");
}
}
CompactScheme::CompactScheme(Profile profile, uint32_t l, uint32_t k)
    :profile_(std::move(profile)),l_(l),k_(k),id_(compact_id++) {
    if (!profile_.compact || l<1 || l>8 || k<1 || k>8) throw std::invalid_argument("Compact profile/dimensions required");
    divisor_=profile_.ciphertext->GetParams().back()->GetModulus().ConvertToInt();
    div_basis_=MakeRnsParams(profile_.ciphertext->GetRingDimension(),{divisor_});
    public_=profile_.packed_public_key?PackedLargerBasis(profile_.ciphertext,profile_.public_extra_bits):
        IndependentLargerBasis(profile_.ciphertext,nullptr,profile_.public_extra_bits,true);
    evaluation_=JoinBases(profile_.ciphertext,profile_.auxiliary);
    source_=IndependentLargerBasis(evaluation_,public_);
    if (source_->GetModulus()<=public_->GetModulus()) throw std::invalid_argument("Compact source must exceed public modulus");
    digits_=(profile_.ciphertext->GetModulus().GetMSB()+profile_.gadget_bits-1)/profile_.gadget_bits+1;
}
RnsParams CompactScheme::basis(uint32_t level) const {
    const auto count=profile_.ciphertext->GetParams().size();
    if(level>=count)throw std::invalid_argument("Compact modulus chain exhausted");
    return PrefixBasis(profile_.ciphertext,count-level);
}
double CompactScheme::encoding_scale() const {
    return double(divisor_)*profile_.ciphertext->GetParams()[profile_.ciphertext->GetParams().size()-2]->GetModulus().ConvertToDouble();
}
void CompactScheme::ValidateRow(const Row& row,const RnsParams& p) const {
    if(row.size()!=k_+1)throw std::invalid_argument("Compact row dimension mismatch");
    for(const auto& c:row)Polynomial(c,p);
}
void CompactScheme::ValidateSecret(const SecretKey& key) const {
    if(key.context!=id_||!key.tag||key.s.size()!=k_)throw std::invalid_argument("Compact secret/context mismatch");
    for(const auto& s:key.s)Polynomial(s,profile_.ciphertext);
}
void CompactScheme::Budget(uint32_t level,double scale,double bound) const {
    if(!std::isfinite(scale)||scale<0x1p20||!std::isfinite(bound)||bound<=0||
       scale*(bound+1)>=basis(level)->GetModulus().ConvertToDouble()/2)
        throw std::invalid_argument("Compact logical scale or public bound exceeds modulus budget");
}
void CompactScheme::Validate(const PairCiphertext& c) const {
    if(c.context!=id_||!c.key_tag||c.level<1)throw std::invalid_argument("Compact pair context/level mismatch");
    Budget(c.level,c.scale,c.bound);ValidateRow(c.high,basis(c.level));ValidateRow(c.low,basis(c.level));
}
void CompactScheme::ValidateTensor(const PairTensor& t) const {
    if(t.context!=id_||!t.key_tag||t.level<1)throw std::invalid_argument("Compact tensor context/level mismatch");
    Budget(t.level,t.scale,t.bound);
    for(const auto* r:{&t.high,&t.low}){
        ValidateRow(r->linear,basis(t.level));
        if(r->quadratic.size()!=k_*k_)throw std::invalid_argument("Compact tensor quadratic dimension mismatch");
        for(const auto& p:r->quadratic)Polynomial(p,basis(t.level));
    }
}
Row CompactScheme::MakeRow(const std::vector<RingPoly>& secret,const RnsParams& target,const RingPoly* embedding) const {
    Row out(k_+1);auto inner=Zero(source_);
    for(uint32_t j=0;j<k_;++j){auto a=Uniform(source_);inner+=a*secret[j];out[j+1]=ScaleAndRound(a,target);}
    out[0]=ScaleAndRound(inner,target);if(embedding)out[0]+=*embedding;return out;
}
KeyPair CompactScheme::KeyGen() const {
    KeyPair out;out.secret_key.context=out.public_key.context=id_;
    out.secret_key.tag=out.public_key.tag=compact_id++;
    std::vector<RingPoly> source_secret;
    for(uint32_t j=0;j<k_;++j){out.secret_key.s.push_back(Ternary(profile_.ciphertext));source_secret.push_back(LiftCentered(out.secret_key.s.back(),source_));}
    for(uint32_t i=0;i<l_;++i)out.public_key.rows.push_back(MakeRow(source_secret,public_));
    return out;
}
RelinearizationKey CompactScheme::RelinGen(const SecretKey& key) const {
    ValidateSecret(key);RelinearizationKey out;out.context=id_;out.key_tag=key.tag;
    std::vector<RingPoly> secret;for(const auto& s:key.s)secret.push_back(LiftCentered(s,source_));
    for(uint32_t i=0;i<k_;++i)for(uint32_t j=profile_.symmetric_relinearization?i:0;j<k_;++j){
        auto power=Integer(1);const auto product=key.s[i]*key.s[j];
        for(uint32_t d=0;d<digits_;++d){const auto embedding=MultiplyInteger(LiftCentered(product,evaluation_),power*profile_.auxiliary->GetModulus());out.rows.push_back(MakeRow(secret,evaluation_,&embedding));power<<=profile_.gadget_bits;}
    }
    return out;
}
RotationKey CompactScheme::RotateKeyGen(const SecretKey& key,int64_t steps) const {
    ValidateSecret(key);RotationKey out;out.exponent=RotationExponent(steps,profile_.ciphertext->GetRingDimension());
    out.switching.context=id_;out.switching.source_tag=out.switching.target_tag=key.tag;
    out.switching.digit_bits=profile_.rotation_gadget_bits;
    out.switching.digit_count=(profile_.ciphertext->GetModulus().GetMSB()+out.switching.digit_bits-1)/out.switching.digit_bits+1;
    std::vector<RingPoly> secret;for(const auto& s:key.s)secret.push_back(LiftCentered(s,source_));
    for(uint32_t j=0;j<k_;++j){auto power=Integer(1);const auto transformed=Automorphism(key.s[j],out.exponent);
        for(uint32_t d=0;d<out.switching.digit_count;++d){const auto embedding=MultiplyInteger(LiftCentered(transformed,evaluation_),power*profile_.auxiliary->GetModulus());out.switching.rows.push_back(MakeRow(secret,evaluation_,&embedding));power<<=out.switching.digit_bits;}
    }
    return out;
}
Plaintext CompactScheme::Encode(const Slots& values,double bound,double scale) const {
    if(!scale)scale=encoding_scale();Budget(0,scale,bound);
    if(values.empty()||values.size()>profile_.slots)throw std::invalid_argument("Compact slot count mismatch");
    for(const auto& z:values)if(!std::isfinite(z.real())||!std::isfinite(z.imag())||std::abs(z)>bound)
        throw std::invalid_argument("Compact input exceeds public bound");
    auto encoded=std::make_shared<lbcrypto::CKKSPackedEncoding>(basis(0),profile_.encoder->GetEncodingParams(),values,1,0,scale,profile_.slots,lbcrypto::COMPLEX);
    encoded->Encode();return {encoded->GetElement<RingPoly>(),encoded->GetScalingFactor(),bound,0,id_};
}
Slots CompactScheme::Decode(const Plaintext& value) const {
    if(value.context!=id_)throw std::invalid_argument("Compact plaintext context mismatch");
    Budget(value.level,value.scale,value.bound);Polynomial(value.polynomial,basis(value.level));
    const auto coefficients=Coefficients(value.polynomial);const auto q=basis(value.level)->GetModulus();const auto half=q>>1;
    auto centered=[&](size_t i){const auto& x=coefficients[i];return (x>half?-(q-x).ConvertToDouble():x.ConvertToDouble())/value.scale;};
    Slots out(coefficients.size()/2);for(size_t i=0;i<out.size();++i)out[i]={centered(i),centered(i+out.size())};
    lbcrypto::DiscreteFourierTransform::FFTSpecial(out,profile_.ciphertext->GetCyclotomicOrder());out.resize(profile_.slots);return out;
}
Ciphertext CompactScheme::Encrypt(const PublicKey& key,const Plaintext& value) const {
    if(value.context!=id_||value.level!=0||key.context!=id_||!key.tag||key.rows.size()!=l_)
        throw std::invalid_argument("Compact public key/plaintext context mismatch");
    Budget(0,value.scale,value.bound);Polynomial(value.polynomial,basis(0));
    Row out(k_+1,Zero(public_));for(const auto& row:key.rows){ValidateRow(row,public_);const auto r=Ternary(public_);for(uint32_t j=0;j<=k_;++j)out[j]+=r*row[j];}
    for(auto& c:out)c=ScaleAndRound(c,basis(0));out[0]+=value.polynomial;
    return {std::move(out),value.scale,value.bound,0,id_,key.tag};
}
std::pair<Row,Row> CompactScheme::DecomposeRow(const Row& value,const RnsParams& from,const RnsParams& target) const {
    ValidateRow(value,from);if(from->GetModulus()!=target->GetModulus()*Integer(divisor_))throw std::invalid_argument("DCP modulus ratio must equal divisor");
    Row high,low;for(const auto& p:value){high.push_back(ScaleAndRound(p,target));low.push_back(SelectBasis(p,target)-MultiplyInteger(high.back(),Integer(divisor_)));}
    return {std::move(high),std::move(low)};
}
Row CompactScheme::RecombineRow(const Row& high,const Row& low) const {
    Row out;for(uint32_t j=0;j<=k_;++j)out.push_back(MultiplyInteger(high[j],Integer(divisor_))+low[j]);return out;
}
PairCiphertext CompactScheme::Decompose(const Ciphertext& value) const {
    if(value.context!=id_||!value.key_tag||value.level!=0)throw std::invalid_argument("DCP requires matching fresh ciphertext");
    Budget(0,value.scale,value.bound);auto parts=DecomposeRow(value.c,basis(0),basis(1));
    PairCiphertext out{std::move(parts.first),std::move(parts.second),value.scale,value.bound,1,id_,value.key_tag};Validate(out);return out;
}
Ciphertext CompactScheme::Recombine(const PairCiphertext& value) const {
    Validate(value);return {RecombineRow(value.high,value.low),value.scale,value.bound,value.level,id_,value.key_tag};
}
Row CompactScheme::Raise(const Row& row,const RnsParams& target) const {
    Row out;for(const auto& p:row)out.push_back(MultiplyInteger(LiftCentered(p,target),Integer(divisor_)));return out;
}
TensorCiphertext CompactScheme::RawTensor(const Row& a,const Row& b) const {
    TensorCiphertext out;out.linear.resize(k_+1);out.linear[0]=a[0]*b[0];
    for(uint32_t j=1;j<=k_;++j)out.linear[j]=a[0]*b[j]+a[j]*b[0];
    for(uint32_t i=1;i<=k_;++i)for(uint32_t j=1;j<=k_;++j)out.quadratic.push_back(a[i]*b[j]);return out;
}
PairTensor CompactScheme::Tensor2(const PairCiphertext& a,const PairCiphertext& b) const {
    Validate(a);Validate(b);if(a.key_tag!=b.key_tag||a.level!=b.level)throw std::invalid_argument("Tensor2 key/level mismatch");
    PairTensor out;out.high=RawTensor(a.high,b.high);out.low=RawTensor(a.high,b.low);const auto other=RawTensor(a.low,b.high);
    for(uint32_t j=0;j<=k_;++j)out.low.linear[j]+=other.linear[j];for(uint32_t j=0;j<k_*k_;++j)out.low.quadratic[j]+=other.quadratic[j];
    out.scale=a.scale*b.scale/double(divisor_);out.bound=a.bound*b.bound;out.level=a.level;out.context=id_;out.key_tag=a.key_tag;ValidateTensor(out);return out;
}
Row CompactScheme::Switch(const std::vector<RingPoly>& multipliers,const std::vector<Row>& rows,const RnsParams& target,uint32_t digit_bits,uint32_t digit_count) const {
    return GadgetSwitch(multipliers,rows,target,evaluation_,profile_.auxiliary,k_+1,digit_bits,digit_count);
}
Row CompactScheme::RawRelin(const TensorCiphertext& tensor,const RelinearizationKey& key,const RnsParams& p) const {
    ValidateRow(tensor.linear,p);if(tensor.quadratic.size()!=k_*k_)throw std::invalid_argument("Compact tensor shape mismatch");
    // s_i*s_j == s_j*s_i in this commutative quotient ring. Aggregate the
    // corresponding ciphertext coefficients BEFORE gadget decomposition, so
    // one switching row per unordered pair represents the exact same phase.
    // This does not omit a term or change a scale/modulus/security setting.
    std::vector<RingPoly> symmetric;
    if(profile_.symmetric_relinearization) {
        symmetric.reserve(k_*(k_+1)/2);
        for(uint32_t i=0;i<k_;++i)for(uint32_t j=i;j<k_;++j) {
            auto combined=tensor.quadratic[i*k_+j];
            if(i!=j)combined+=tensor.quadratic[j*k_+i];
            symmetric.push_back(std::move(combined));
        }
    }
    const auto& coefficients=profile_.symmetric_relinearization?symmetric:tensor.quadratic;
    auto out=tensor.linear;auto switched=Switch(coefficients,key.rows,p,profile_.gadget_bits,digits_);for(uint32_t j=0;j<=k_;++j)out[j]+=switched[j];return out;
}
PairCiphertext CompactScheme::Relin2(const PairTensor& tensor,const RelinearizationKey& key,Row* raised_trace,Row* low_trace) const {
    ValidateTensor(tensor);if(key.context!=id_||key.key_tag!=tensor.key_tag)throw std::invalid_argument("Compact relinearization key mismatch");
    const auto p=basis(tensor.level),raised=JoinBases(p,div_basis_);
    auto high=tensor.high;high.linear=Raise(high.linear,raised);high.quadratic=Raise(high.quadratic,raised);
    const auto raised_result=RawRelin(high,key,raised);auto parts=DecomposeRow(raised_result,raised,p);
    const auto low=RawRelin(tensor.low,key,p);for(uint32_t j=0;j<=k_;++j)parts.second[j]+=low[j];
    if(raised_trace)*raised_trace=raised_result;
    if(low_trace)*low_trace=low;
    PairCiphertext out{std::move(parts.first),std::move(parts.second),tensor.scale,tensor.bound,tensor.level,id_,tensor.key_tag};Validate(out);return out;
}
PairCiphertext CompactScheme::Rescale2(const PairCiphertext& value) const {
    Validate(value);const auto target=basis(value.level+1);const auto old=basis(value.level);
    PairCiphertext out=value;out.level++;out.scale/= (old->GetModulus()/target->GetModulus()).ConvertToDouble();
    const auto combined=RecombineRow(value.high,value.low);
    for(uint32_t j=0;j<=k_;++j){out.high[j]=ScaleAndRound(value.high[j],target);const auto rescaled=ScaleAndRound(combined[j],target);out.low[j]=rescaled-MultiplyInteger(out.high[j],Integer(divisor_));}
    Validate(out);return out;
}
PairCiphertext CompactScheme::Mult2(const PairCiphertext& a,const PairCiphertext& b,const RelinearizationKey& key) const {return Rescale2(Relin2(Tensor2(a,b),key));}
PairCiphertext CompactScheme::Add(const PairCiphertext& a,const PairCiphertext& b) const {
    Validate(a);Validate(b);if(a.key_tag!=b.key_tag||a.level!=b.level||std::abs(a.scale/b.scale-1)>1e-12)throw std::invalid_argument("Compact Add key/level/scale mismatch");
    auto out=a;out.bound+=b.bound;for(uint32_t j=0;j<=k_;++j){out.high[j]+=b.high[j];out.low[j]+=b.low[j];}Validate(out);return out;
}
Row CompactScheme::RawSwitch(const Row& row,const SwitchingKey& key,const RnsParams& p) const {
    ValidateRow(row,p);auto switched=Switch({row.begin()+1,row.end()},key.rows,p,key.digit_bits,key.digit_count);Row out;out.push_back(row[0]-switched[0]);
    for(uint32_t j=1;j<=k_;++j)out.push_back(Zero(p)-switched[j]);return out;
}
PairCiphertext CompactScheme::Rotate(const PairCiphertext& value,const RotationKey& key) const {
    Validate(value);if(key.switching.context!=id_||key.switching.source_tag!=value.key_tag||key.switching.target_tag!=value.key_tag)throw std::invalid_argument("Compact rotation key mismatch");
    if(key.switching.digit_bits!=profile_.rotation_gadget_bits||key.switching.digit_count!=(profile_.ciphertext->GetModulus().GetMSB()+profile_.rotation_gadget_bits-1)/profile_.rotation_gadget_bits+1)
        throw std::invalid_argument("Compact rotation digit metadata mismatch");
    auto input=value;for(auto* row:{&input.high,&input.low})for(auto& p:*row)p=Automorphism(p,key.exponent);
    const auto p=basis(input.level),raised=JoinBases(p,div_basis_);auto parts=DecomposeRow(RawSwitch(Raise(input.high,raised),key.switching,raised),raised,p);
    const auto low=RawSwitch(input.low,key.switching,p);for(uint32_t j=0;j<=k_;++j)parts.second[j]+=low[j];
    input.high=std::move(parts.first);input.low=std::move(parts.second);Validate(input);return input;
}
RingPoly CompactScheme::PhaseRow(const SecretKey& key,const Row& row,const RnsParams& p) const {
    ValidateSecret(key);ValidateRow(row,p);auto out=row[0];for(uint32_t j=0;j<k_;++j)out-=row[j+1]*SelectBasis(key.s[j],p);return out;
}
RingPoly CompactScheme::Phase(const SecretKey& key,const Ciphertext& value) const {
    if(value.context!=id_||value.key_tag!=key.tag)throw std::invalid_argument("Compact ciphertext/key mismatch");
    Budget(value.level,value.scale,value.bound);return PhaseRow(key,value.c,basis(value.level));
}
RingPoly CompactScheme::PhaseTensor(const SecretKey& key,const TensorCiphertext& t,const RnsParams& p) const {
    auto out=PhaseRow(key,t.linear,p);if(t.quadratic.size()!=k_*k_)throw std::invalid_argument("Compact quadratic shape mismatch");
    for(uint32_t i=0;i<k_;++i)for(uint32_t j=0;j<k_;++j)out+=t.quadratic[i*k_+j]*SelectBasis(key.s[i],p)*SelectBasis(key.s[j],p);return out;
}
Slots CompactScheme::Decrypt(const SecretKey& key,const Ciphertext& value,uint32_t smudge) const {
    auto phase=Phase(key,value);
    if(smudge){RingPoly::DugType random;random.SetModulus(lbcrypto::NativeInteger(uint64_t(smudge)*2+1));const auto samples=random.GenerateVector(profile_.ciphertext->GetRingDimension());std::vector<int64_t> noise;for(uint32_t i=0;i<samples.GetLength();++i)noise.push_back(int64_t(samples[i].ConvertToInt())-smudge);phase+=FromSignedCoefficients(basis(value.level),noise);}
    return Decode({phase,value.scale,value.bound,value.level,id_});
}
} // namespace mlwr
