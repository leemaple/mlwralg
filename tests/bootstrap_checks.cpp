#include "mlwr/bootstrap.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>

int main() {
    try {
        auto profile=mlwr::MakeBootstrapProfile({});
        mlwr::ResearchScheme scheme(profile.module,2,3);
        mlwr::BootstrapBridge bridge(scheme,profile);
        auto keys=scheme.KeyGen();auto bk=bridge.KeyGen(keys.secret_key);
        mlwr::Slots input;for(int j=0;j<8;++j)input.emplace_back((j-4)/8.,(j%3-1)/6.);
        auto c=scheme.Encrypt(keys.public_key,scheme.Encode(input,0,1));
        c.level=profile.module.depth-1;
        for(auto& part:c.c)part=mlwr::SelectBasis(part,scheme.basis(c.level));
        auto native=bridge.Fold(c,bk);
        auto imported=bridge.Import(native,bk,1);
        auto all=scheme.DecodeAll({scheme.Phase(keys.secret_key,imported),imported.scale,1,imported.level,imported.context});
        double worst=0;
        for(size_t j=0;j<all.size();++j)worst=std::max(worst,std::abs(all[j]-input[j%8]));
        if(!std::isfinite(worst)||worst>0x1p-20)throw std::runtime_error("Fold numeric failure");
        unsigned checks=1;
        auto reject=[&](const std::function<void()>& f) {
            try{f();}catch(const std::invalid_argument&){++checks;return;}
            throw std::runtime_error("Invalid bridge state accepted");
        };
        auto bad=c;bad.context++;reject([&]{bridge.Fold(bad,bk);});
        bad=c;bad.key_tag++;reject([&]{bridge.Fold(bad,bk);});
        bad=c;bad.c.pop_back();reject([&]{bridge.Fold(bad,bk);});
        bad=c;bad.level--;reject([&]{bridge.Fold(bad,bk);});
        bad=c;bad.scale=0;reject([&]{bridge.Fold(bad,bk);});
        auto badkey=bk;badkey.context++;bad=c;bad.context=badkey.context;
        reject([&]{bridge.Fold(bad,badkey);});
        badkey=bk;badkey.folding.front()=nullptr;reject([&]{bridge.Fold(c,badkey);});
        badkey=bk;badkey.source_tags.front()="wrong";reject([&]{bridge.Fold(c,badkey);});
        auto badnative=native->Clone();badnative->SetKeyTag("wrong");reject([&]{bridge.Import(badnative,bk,1);});
        badnative=native->Clone();badnative->SetNoiseScaleDeg(2);reject([&]{bridge.Import(badnative,bk,1);});
        badnative=native->Clone();badnative->SetSlots(4);reject([&]{bridge.Import(badnative,bk,1);});
        reject([&]{bridge.Import(nullptr,bk,1);});
        reject([&]{bridge.Refresh(c,bk,3);});
        std::cout<<"{\"checks\":"<<checks<<",\"max_error\":"<<worst<<",\"passed\":true}\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
