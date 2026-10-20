#include "mlwr/scheme.hpp"
#include <cmath>
#include <iostream>
#include <stdexcept>

int main() {
    try {
        auto p=mlwr::OpenFheProfile(1,8,16384,41,45);
        const auto prime=lbcrypto::LastPrime<lbcrypto::NativeInteger>(20,32768);
        p.auxiliary=mlwr::MakeRnsParams(16384,{prime.ConvertToInt()});
        p.standard_gadget_bits=16;
        mlwr::ResearchScheme scheme(p,2,3);
        const auto keys=scheme.KeyGen(),other=scheme.KeyGen();
        const auto relin=scheme.RelinGen(keys.secret_key);
        const auto switching=scheme.KSGen(other.secret_key,keys.secret_key);
        const auto rotation=scheme.RotateKeyGen(keys.secret_key,1);
        mlwr::Slots x,y,xy,shifted;
        for(int i=0;i<8;++i) {
            x.emplace_back((i-4)/8.,(i%3-1)/8.);
            y.emplace_back((7-i)/10.,(i%2?-1.:1.)/6.);
            xy.push_back(x.back()*y.back());
        }
        for(int i=0;i<8;++i)shifted.push_back(x[(i+1)%8]);
        // OpenFheProfile uses FLEXIBLEAUTOEXT; consume its initial extension
        // tower before ordinary multiplication, as the main application does.
        const auto a=scheme.Rescale(scheme.Encrypt(keys.public_key,scheme.Encode(x,0,1)));
        const auto b=scheme.Rescale(scheme.Encrypt(keys.public_key,scheme.Encode(y,0,1)));
        double worst=0;
        auto check=[&](const mlwr::Slots& actual,const mlwr::Slots& expected) {
            if(actual.size()!=expected.size())throw std::runtime_error("Slot count mismatch");
            for(size_t i=0;i<actual.size();++i) {
                const auto e=std::abs(actual[i]-expected[i]);
                if(!std::isfinite(e)||e>0x1p-20)throw std::runtime_error("Standard gadget numeric failure");
                worst=std::max(worst,e);
            }
        };
        check(scheme.Decrypt(keys.secret_key,scheme.Rescale(scheme.Mult(a,b,relin))),xy);
        check(scheme.Decrypt(other.secret_key,scheme.KeySwitch(a,switching)),x);
        check(scheme.Decrypt(keys.secret_key,scheme.Rotate(a,rotation)),shifted);
        auto bad=switching;bad.digit_bits++;
        bool rejected=false;try{scheme.KeySwitch(a,bad);}catch(const std::invalid_argument&){rejected=true;}
        if(!rejected)throw std::runtime_error("Invalid gadget metadata accepted");
        std::cout<<"{\"passed\":true,\"max_error\":"<<worst<<",\"relin_rows\":"<<relin.rows.size()<<"}\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
