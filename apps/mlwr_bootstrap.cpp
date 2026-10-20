#include "mlwr/bootstrap.hpp"

#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <set>
#include <algorithm>
#include <map>
#include <stdexcept>
#include <string>

namespace {
using Clock = std::chrono::steady_clock;
double Milliseconds(Clock::time_point start) {
    return std::chrono::duration<double,std::milli>(Clock::now()-start).count();
}
double Error(const mlwr::Slots& a, const mlwr::Slots& b) {
    if(a.size()!=b.size()) throw std::runtime_error("Slot count mismatch");
    double result=0;
    for(size_t i=0;i<a.size();++i) {
        if(!std::isfinite(b[i].real()) || !std::isfinite(b[i].imag())) throw std::runtime_error("Nonfinite decoded slot");
        result=std::max(result,std::abs(a[i]-b[i]));
    }
    return result;
}
double RepeatedError(const mlwr::Slots& expected,const mlwr::Slots& actual) {
    if(expected.empty() || actual.size()%expected.size())throw std::runtime_error("Repeated layout size mismatch");
    double result=0;
    for(size_t i=0;i<actual.size();++i) {
        const auto error=std::abs(actual[i]-expected[i%expected.size()]);
        if(!std::isfinite(error))throw std::runtime_error("Nonfinite full-slot error");
        result=std::max(result,error);
    }
    return result;
}
void SlotsJson(const mlwr::Slots& x) {
    std::cout << '[';
    for(size_t i=0;i<x.size();++i) {if(i)std::cout<<',';std::cout<<'['<<x[i].real()<<','<<x[i].imag()<<']';}
    std::cout << ']';
}
std::map<std::string,std::string> Arguments(int argc,char** argv) {
    std::map<std::string,std::string> result;
    const auto trim=[](std::string x) {
        const auto begin=x.find_first_not_of(" \t\r\n");
        return begin==std::string::npos?std::string():x.substr(begin,x.find_last_not_of(" \t\r\n")-begin+1);
    };
    std::string config;
    for(int i=1;i<argc;++i)if(std::string(argv[i])=="--config") {
        if(!config.empty() || i+1>=argc)throw std::invalid_argument("One --config file required");
        config=argv[++i];
    }
    if(!config.empty()) {
        std::ifstream input(config);if(!input)throw std::invalid_argument("Cannot open config: "+config);
        std::string line;
        while(std::getline(input,line)) {
            line=trim(line.substr(0,line.find('#')));if(line.empty())continue;
            const auto equal=line.find('=');
            if(equal==std::string::npos)throw std::invalid_argument("Config lines must be key=value");
            auto key=trim(line.substr(0,equal));std::replace(key.begin(),key.end(),'_','-');
            if(key=="N")key="n";
            if(!result.emplace("--"+key,trim(line.substr(equal+1))).second)
                throw std::invalid_argument("Duplicate config option: "+key);
        }
    }
    std::set<std::string> cli;
    for(int i=1;i<argc;++i) {
        const std::string key=argv[i];
        if(key=="--config"){++i;continue;}
        if(!cli.insert(key).second)throw std::invalid_argument("Duplicate CLI option: "+key);
        if(key=="--print-parameters"){result[key]="1";continue;}
        if(i+1>=argc)throw std::invalid_argument("Missing argument value: "+key);
        result[key]=argv[++i];
    }
    return result;
}
mlwr::Ciphertext Drop(const mlwr::ResearchScheme& scheme, const mlwr::Ciphertext& x, uint32_t level) {
    if(level<x.level) throw std::invalid_argument("A projection cannot restore levels");
    auto result=x;result.level=level;
    for(auto& c:result.c)c=mlwr::SelectBasis(c,scheme.basis(level));
    if(result.scale*(result.bound+1)>=scheme.basis(level)->GetModulus().ConvertToDouble()/2)
        throw std::invalid_argument("Projection would exceed the public message budget");
    return result;
}
}

int main(int argc,char** argv) {
    try {
        mlwr::BootstrapOptions o;
        uint32_t l=2,k=2,circuit_depth=8,precision=20,iterations=1,correction_precision=0,family=0;
        bool print=false,probe=false,hybrid=false;
        for(const auto& [arg,token]:Arguments(argc,argv)) {
            if(arg=="--print-parameters"){print=true;continue;}
            if(token.empty() || token.find_first_not_of("0123456789")!=std::string::npos)
                throw std::invalid_argument("Invalid unsigned integer: "+arg);
            size_t pos=0;const auto parsed=std::stoul(token,&pos);
            if(pos!=token.size()||parsed>UINT32_MAX)throw std::invalid_argument("Invalid unsigned integer");
            const auto v=static_cast<uint32_t>(parsed);
            if(arg=="--n")o.n=v;else if(arg=="--slots")o.slots=v;
            else if(arg=="--scale-bits")o.scale_bits=v;else if(arg=="--first-mod-bits")o.first_bits=v;
            else if(arg=="--security-bits")o.security_bits=v;else if(arg=="--usable-levels")o.usable_levels=v;
            else if(arg=="--cts-levels")o.cts_levels=v;else if(arg=="--stc-levels")o.stc_levels=v;
            else if(arg=="--large-digits")o.large_digits=v;else if(arg=="--correction-factor")o.correction_factor=v;
            else if(arg=="--module-gadget-bits")o.module_gadget_bits=v;
            else if(arg=="--paper-sparse") {if(v>1)throw std::invalid_argument("paper-sparse must be 0 or 1");o.paper_sparse=v;}
            else if(arg=="--hybrid-multiply") {if(v>1)throw std::invalid_argument("hybrid-multiply must be 0 or 1");hybrid=v;}
            else if(arg=="--refresh-probe") {if(v>1)throw std::invalid_argument("refresh-probe must be 0 or 1");probe=v;}
            else if(arg=="--project-repeated") {if(v>1)throw std::invalid_argument("project-repeated must be 0 or 1");o.project_repeated=v;}
            else if(arg=="--flexible-scaling") {if(v>1)throw std::invalid_argument("flexible-scaling must be 0 or 1");o.flexible_scaling=v;}
            else if(arg=="--l")l=v;else if(arg=="--k")k=v;
            else if(arg=="--circuit-depth")circuit_depth=v;else if(arg=="--precision-bits")precision=v;
            else if(arg=="--iterations")iterations=v;else if(arg=="--correction-precision")correction_precision=v;
            else if(arg=="--family")family=v;else throw std::invalid_argument("Unknown option: "+arg);
        }
        if(l<1||l>8||k<1||k>8||!circuit_depth||circuit_depth>100||precision<8||precision>40||family>2)
            throw std::invalid_argument("l/k 1..8, circuit-depth 1..100, precision 8..40, family 0..2 required");
        if((iterations!=1 && iterations!=2) || (iterations==2 && (correction_precision<1 || correction_precision>30)))
            throw std::invalid_argument("iterations 1/2 and correction-precision 1..30 for iteration 2 required");
        std::cout<<std::setprecision(17);
        auto p=mlwr::MakeBootstrapProfile(o);
        if(print){mlwr::WriteBootstrapProfile(std::cout,p);std::cout<<'\n';return 0;}
        std::map<std::string,double> timing;
        mlwr::ResearchScheme scheme(p.module,l,k);
        mlwr::BootstrapBridge bridge(scheme,p);
        std::cerr<<"Key generation N="<<o.n<<", total depth="<<p.module.depth<<"\n";
        auto start=Clock::now();auto keys=scheme.KeyGen();timing["module_keygen_ms"]=Milliseconds(start);
        std::cerr<<"Bootstrap and folding key generation\n";
        start=Clock::now();auto boot_key=bridge.KeyGen(keys.secret_key);timing["bootstrap_keygen_ms"]=Milliseconds(start);
        mlwr::RelinearizationKey relin;
        if(!probe && !hybrid) {
            std::cerr<<"Module relinearization key generation\n";
            start=Clock::now();relin=scheme.RelinGen(keys.secret_key);timing["module_relin_keygen_ms"]=Milliseconds(start);
        }
        const auto decode_all=[&](const mlwr::Ciphertext& c) {
            return scheme.DecodeAll({scheme.Phase(keys.secret_key,c),c.scale,c.bound,c.level,c.context});
        };
        mlwr::Slots input;
        for(uint32_t j=0;j<o.slots;++j) {
            if(family==0) input.emplace_back((j%2?-1:1)*(0.2+0.5*(j+1)/o.slots),0);
            else if(family==1)input.push_back(std::polar(0.75,0.37*j));
            else input.emplace_back(0.53*std::sin(3.1*j+0.2),0.47*std::cos(1.7*j+0.8));
        }
        auto reference=input;
        start=Clock::now();auto fresh=scheme.Encrypt(keys.public_key,scheme.Encode(input,0,1));
        timing["encrypt_ms"]=Milliseconds(start);
        const auto fresh_decoded=decode_all(fresh);
        const auto fresh_error=RepeatedError(input,fresh_decoded);
        std::cerr<<"Fresh error="<<fresh_error<<", scale="<<fresh.scale<<"\n";
        const std::complex<double> multiplier=std::polar(0.985,0.13);
        const mlwr::Slots factor(o.slots,multiplier);
        start=Clock::now();
        auto factor_fresh=scheme.Encrypt(keys.public_key,scheme.Encode(factor,0,1));
        timing["factor_encrypt_ms"]=Milliseconds(start);
        lbcrypto::Ciphertext<mlwr::RingPoly> native_factor;
        if(hybrid && !probe) {
            start=Clock::now();native_factor=bridge.Fold(factor_fresh,boot_key);
            timing["factor_fold_ms"]=Milliseconds(start);
        }
        // Deliberately depleted input. Later bootstraps occur only after real
        // multiplication consumes the restored chain. Projection is not refresh.
        auto current=Drop(scheme,fresh,p.module.depth-1);
        auto roundtrip=bridge.Import(bridge.Fold(current,boot_key),boot_key,1);
        const auto fold_decoded=decode_all(roundtrip);
        const auto fold_error=RepeatedError(input,fold_decoded);
        std::cerr<<"Fold error="<<fold_error<<", scale="<<roundtrip.scale<<"\n";
        double native_fold_error=0,native_control_error=0;
        if(probe) {
            // Client-only diagnostic control: same secret/parameters, native
            // encryption and native decoding. Never called by Refresh.
            auto native_secret=std::make_shared<lbcrypto::PrivateKeyImpl<mlwr::RingPoly>>(p.module.encoder);
            native_secret->SetKeyTag(boot_key.native_tag);
            mlwr::RingPoly zero(p.module.ciphertext,EVALUATION,true);
            native_secret->SetPrivateElement(zero-keys.secret_key.s.front());
            lbcrypto::Plaintext native_plain;
            p.module.encoder->Decrypt(native_secret,bridge.Fold(current,boot_key),&native_plain);
            native_plain->SetLength(o.slots);
            native_fold_error=Error(input,native_plain->GetCKKSPackedValue());
            auto control_plain=p.module.encoder->MakeCKKSPackedPlaintext(input,1,p.module.depth-1,nullptr,o.slots);
            auto control=p.module.encoder->Encrypt(native_secret,control_plain);
            control=p.module.encoder->EvalBootstrap(control,iterations,correction_precision);
            if(control->GetNoiseScaleDeg()>1)
                p.module.encoder->GetScheme()->ModReduceInternalInPlace(control,control->GetNoiseScaleDeg()-1);
            if(o.project_repeated)control=bridge.ProjectRepeated(control);
            native_control_error=RepeatedError(input,decode_all(bridge.Import(control,boot_key,1)));
            std::cerr<<"Native decode Fold error="<<native_fold_error<<", native encryption/bootstrap control="<<native_control_error<<"\n";
        }
        struct Record{std::string operation;uint32_t depth,before,after;double ms,error,scale;mlwr::Slots decoded;std::map<std::string,double> phases;};
        std::vector<Record> records;
        uint32_t refreshes=0;
        double max_error=std::max(fresh_error,fold_error);
        start=Clock::now();
        for(uint32_t d=0;d<circuit_depth && max_error<=std::ldexp(1.0,-static_cast<int>(precision));++d) {
            if(current.level>=p.module.depth-1) {
                const auto before=current.level;const auto boot_start=Clock::now();
                std::cerr<<"Refresh "<<refreshes+1<<" at circuit layer "<<d<<"\n";
                std::map<std::string,double> phases;
                current=bridge.Refresh(current,boot_key,iterations,correction_precision,&phases);
                const auto ms=Milliseconds(boot_start);auto decoded=decode_all(current);
                const auto error=RepeatedError(reference,decoded);max_error=std::max(max_error,error);
                std::cerr<<"Refreshed level="<<current.level<<", scale="<<current.scale
                         <<", error="<<error<<", slot0="<<decoded[0]<<"\n";
                records.push_back({"bootstrap",d,before,current.level,ms,error,current.scale,std::move(decoded),std::move(phases)});
                ++refreshes;
            }
            if(probe || max_error>std::ldexp(1.0,-static_cast<int>(precision)))break;
            const auto before=current.level;const auto mult_start=Clock::now();
            std::map<std::string,double> phases;
            if(hybrid)current=bridge.HybridMultiply(current,native_factor,boot_key,1,&phases);
            else {
                auto phase_start=Clock::now();auto f=Drop(scheme,factor_fresh,current.level);
                phases["align_ms"]=Milliseconds(phase_start);
                phase_start=Clock::now();auto tensor=scheme.Tensor(current,f);
                phases["tensor_ms"]=Milliseconds(phase_start);
                phase_start=Clock::now();auto linear=scheme.Relinearize(tensor,relin);
                phases["relinearize_ms"]=Milliseconds(phase_start);
                phase_start=Clock::now();current=scheme.Rescale(linear);
                phases["rescale_ms"]=Milliseconds(phase_start);
            }
            const auto ms=Milliseconds(mult_start);for(auto& z:reference)z*=multiplier;
            auto decoded=decode_all(current);const auto error=RepeatedError(reference,decoded);
            max_error=std::max(max_error,error);
            records.push_back({"multiply_rescale",d+1,before,current.level,ms,error,current.scale,std::move(decoded),std::move(phases)});
            std::cerr<<"Layer "<<d+1<<"/"<<circuit_depth<<", error="<<error<<"\n";
        }
        timing["circuit_with_client_checks_ms"]=Milliseconds(start);
        double evaluator_ms=timing["factor_fold_ms"];for(const auto& r:records)evaluator_ms+=r.ms;
        timing["evaluator_total_ms"]=evaluator_ms;
        const bool completed=probe ? refreshes==1 : !records.empty() && records.back().depth==circuit_depth;
        const bool pass=completed && max_error<=std::ldexp(1.0,-static_cast<int>(precision)) && refreshes>=(probe?1u:2u);
        std::cout<<"{\"schema_version\":1,\"experiment_class\":\"diagnostic\",\"profile\":";
        mlwr::WriteBootstrapProfile(std::cout,p);
        std::cout<<",\"validation_scope\":\""<<(probe?"refresh_only":"two_refresh_continuation")<<'"'
            <<",\"multiplication_backend\":\""<<(hybrid?"folded_rlwe_hybrid":"module_balanced_gadget")<<'"'
            <<",\"decoded_layout\":\"all_N_over_2_slots_repeating_input\""
            <<",\"l\":"<<l<<",\"k\":"<<k<<",\"family\":"<<family<<",\"circuit_depth\":"<<(probe?0:circuit_depth)
            <<",\"precision_bits\":"<<precision<<",\"target_error\":"<<std::ldexp(1.0,-static_cast<int>(precision))
            <<",\"iterations\":"<<iterations<<",\"correction_precision\":"<<correction_precision
            <<",\"refresh_count\":"<<refreshes<<",\"fresh_error\":"<<fresh_error<<",\"fold_error\":"<<fold_error;
        std::cout<<",\"native_fold_decode_error\":";
        if(probe)std::cout<<native_fold_error;else std::cout<<"null";
        std::cout<<",\"native_encrypt_bootstrap_control_error\":";
        if(probe)std::cout<<native_control_error;else std::cout<<"null";
        std::cout<<",\"max_error\":"<<max_error<<",\"all_checks_passed\":"<<(pass?"true":"false")<<",\"input\":";
        SlotsJson(input);std::cout<<",\"fresh_decoded\":";SlotsJson(fresh_decoded);
        std::cout<<",\"fold_decoded\":";SlotsJson(fold_decoded);
        std::cout<<",\"factor\":["<<multiplier.real()<<','<<multiplier.imag()<<"],\"records\":[";
        for(size_t i=0;i<records.size();++i) {
            const auto& r=records[i];if(i)std::cout<<',';
            std::cout<<"{\"operation\":\""<<r.operation<<"\",\"depth\":"<<r.depth
                <<",\"level_before\":"<<r.before<<",\"level_after\":"<<r.after<<",\"ms\":"<<r.ms
                <<",\"max_error\":"<<r.error<<",\"scale\":"<<r.scale<<",\"decoded\":";
            SlotsJson(r.decoded);std::cout<<",\"phases_ms\":{";
            bool phase_first=true;for(const auto& [name,ms]:r.phases) {
                if(!phase_first)std::cout<<',';phase_first=false;std::cout<<'"'<<name<<"\":"<<ms;
            }
            std::cout<<"}}";
        }
        std::cout<<"],\"timings_ms\":{";bool first=true;
        for(const auto& [name,ms]:timing){if(!first)std::cout<<',';first=false;std::cout<<'"'<<name<<"\":"<<ms;}
        std::cout<<"}}\n";
        return pass?0:2;
    } catch(const std::exception& e){std::cerr<<"Bootstrap experiment failed: "<<e.what()<<'\n';return 1;}
}
