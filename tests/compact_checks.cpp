#include "mlwr/compact.hpp"
#include <cmath>
#include <functional>
#include <iostream>
#include <stdexcept>
using namespace mlwr;
namespace {
unsigned checks=0; double worst=0;
void Require(bool x){++checks;if(!x)throw std::runtime_error("Compact contract failure");}
void Reject(const std::function<void()>& f){try{f();}catch(const std::invalid_argument&){++checks;return;}throw std::runtime_error("Invalid compact state accepted");}
void Close(const Slots& a,const Slots& b){Require(a.size()==b.size());for(size_t i=0;i<a.size();++i){const auto e=std::abs(a[i]-b[i]);Require(std::isfinite(e)&&e<=0x1p-20);worst=std::max(worst,e);}}
}
int main(){try{
    CompactScheme scheme(CompactProfile(1,8,4096,28,48,128,17,20,16),2,2);
    const auto keys=scheme.KeyGen();const auto relin=scheme.RelinGen(keys.secret_key);
    Require(scheme.profile().checked_public_bits<=109);
    Require(scheme.public_basis()->GetModulus()>scheme.basis(0)->GetModulus());
    Require(relin.rows.size()==4*scheme.digits());
    const Slots x{-.5,-.25,0,.125,.25,.5,.75,1};Slots expected;for(const auto& z:x)expected.push_back(z*z);
    const auto fresh=scheme.Encrypt(keys.public_key,scheme.Encode(x,1.));
    Close(scheme.Decrypt(keys.secret_key,fresh),x);
    const auto pair=scheme.Decompose(fresh);const auto combined=scheme.Recombine(pair);
    for(size_t j=0;j<3;++j)Require(combined.c[j]==SelectBasis(fresh.c[j],scheme.basis(1)));
    const auto tensor=scheme.Tensor2(pair,pair);const auto p=scheme.basis(1);
    const auto tensor_phase=MultiplyInteger(scheme.PhaseTensor(keys.secret_key,tensor.high,p),Integer(scheme.divisor()))+scheme.PhaseTensor(keys.secret_key,tensor.low,p);
    const auto plain_phase=scheme.Phase(keys.secret_key,pair),low=scheme.PhaseRow(keys.secret_key,pair.low,p);
    Require(MultiplyInteger(tensor_phase,Integer(scheme.divisor()))==plain_phase*plain_phase-low*low);
    const auto relinearized=scheme.Relin2(tensor,relin);const auto result=scheme.Rescale2(relinearized);
    for(size_t j=0;j<3;++j)Require(scheme.Recombine(result).c[j]==ScaleAndRound(scheme.Recombine(relinearized).c[j],scheme.basis(2)));
    Close(scheme.Decrypt(keys.secret_key,result),expected);
    const auto rotation=scheme.RotateKeyGen(keys.secret_key,-1);Slots shifted;for(size_t i=0;i<x.size();++i)shifted.push_back(x[(i+7)%8]);
    Close(scheme.Decrypt(keys.secret_key,scheme.Rotate(pair,rotation)),shifted);
    Slots shifted_product;for(size_t i=0;i<x.size();++i)shifted_product.push_back(expected[(i+7)%8]);
    Close(scheme.Decrypt(keys.secret_key,scheme.Rotate(result,rotation)),shifted_product);
    auto bad=pair;bad.high.pop_back();Reject([&]{scheme.Tensor2(bad,pair);});
    bad=pair;bad.context++;Reject([&]{scheme.Recombine(bad);});
    bad=pair;bad.level=0;Reject([&]{scheme.Recombine(bad);});
    auto badkey=relin;badkey.rows.pop_back();Reject([&]{scheme.Relin2(tensor,badkey);});
    badkey=relin;badkey.key_tag++;Reject([&]{scheme.Relin2(tensor,badkey);});
    auto badtensor=tensor;badtensor.low.quadratic.pop_back();Reject([&]{scheme.Relin2(badtensor,relin);});
    auto badrotation=rotation;badrotation.switching.digit_count=0;Reject([&]{scheme.Rotate(pair,badrotation);});
    Reject([&]{ResearchScheme wrong(scheme.profile(),2,2);});
    Reject([&]{scheme.Rescale2(result);});
    std::cout<<"{\"checks\":"<<checks<<",\"max_error\":"<<worst<<",\"passed\":true}\n";
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
