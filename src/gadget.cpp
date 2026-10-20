#include "mlwr/gadget.hpp"
#include <algorithm>
#include <stdexcept>

namespace mlwr {
namespace {
RingPoly Zero(const RnsParams& p) { return RingPoly(p,EVALUATION,true); }
void Polynomial(const RingPoly& x,const RnsParams& p) {
    if(x.GetFormat()!=EVALUATION || !SameBasis(x.GetParams(),p))
        throw std::invalid_argument("Gadget polynomial basis/format mismatch");
}
void ValidateRow(const Row& row,const RnsParams& p,uint32_t columns) {
    if(row.size()!=columns)throw std::invalid_argument("Gadget row shape mismatch");
    for(const auto& x:row)Polynomial(x,p);
}
// Gadget digits are native signed integers, so constructing their RNS
// residues needs no composite CRT/big-integer conversion.
RingPoly SmallPolynomial(const RnsParams& params,const std::vector<int64_t>& digits) {
    RingPoly out(params,COEFFICIENT,true);
    for(size_t t=0;t<params->GetParams().size();++t){
        const auto modulus=params->GetParams()[t]->GetModulus();const auto q=modulus.ConvertToInt();
        lbcrypto::NativeVector values(digits.size(),modulus);
        for(size_t i=0;i<digits.size();++i){const auto x=digits[i];const auto r=uint64_t(x<0?-x:x)%q;values[i]=lbcrypto::NativeInteger(x<0&&r?q-r:r);}
        lbcrypto::NativePoly tower(params->GetParams()[t],COEFFICIENT,true);tower.SetValues(std::move(values),COEFFICIENT);out.SetElementAtIndex(t,std::move(tower));
    }
    out.SetFormat(EVALUATION);return out;
}
}
Row GadgetSwitch(const std::vector<RingPoly>& multipliers,const std::vector<Row>& rows,
                 const RnsParams& target,const RnsParams& key_basis,
                 const RnsParams& auxiliary,uint32_t columns,
                 uint32_t digit_bits,uint32_t digit_count) {
    if(digit_bits<1||digit_bits>30||rows.size()!=multipliers.size()*digit_count)throw std::invalid_argument("Global gadget key row count mismatch");
    const auto n=target->GetRingDimension();const uint64_t base=uint64_t{1}<<digit_bits;const Integer big_base(base);
    const auto extended=JoinBases(target,auxiliary);
    Row out(columns,Zero(extended));
    for(size_t i=0;i<multipliers.size();++i){
        Polynomial(multipliers[i],target);const auto q=target->GetModulus();const auto coefficients=Coefficients(multipliers[i]);
        std::vector<std::vector<int64_t>> digits(digit_count,std::vector<int64_t>(n));
        for(size_t c=0;c<n;++c){const bool negative=coefficients[c]>(q>>1);auto magnitude=negative?q-coefficients[c]:coefficients[c];
            for(uint32_t d=0;d<digit_count;++d){const auto remainder=magnitude.Mod(big_base).ConvertToInt();
                const int64_t digit=remainder>base/2?int64_t(remainder)-int64_t(base):int64_t(remainder);
                digits[d][c]=negative?-digit:digit;
                magnitude=digit<0?(magnitude+Integer(uint64_t(-digit)))/big_base:(magnitude-Integer(uint64_t(digit)))/big_base;
            }
            if(magnitude!=Integer(0))throw std::invalid_argument("Global balanced decomposition overflow");
        }
        for(uint32_t d=0;d<digit_count;++d){const auto& row=rows[i*digit_count+d];ValidateRow(row,key_basis,columns);
            if(std::all_of(digits[d].begin(),digits[d].end(),[](int64_t x){return x==0;}))continue;
            const auto digit=SmallPolynomial(extended,digits[d]);
            for(uint32_t j=0;j<columns;++j){
                if(SameBasis(row[j].GetParams(),extended))out[j]+=digit*row[j];
                else out[j]+=digit*SelectBasis(row[j],extended);
            }
        }
    }
    for(auto& component:out)component=ScaleAndRound(component,target);
    return out;

}
} // namespace mlwr
