#pragma once

#include "mlwr/scheme.hpp"
#include <map>

namespace mlwr {

// The evaluation key contains no secret key. Folding changes the k-component
// negative-secret phase into CKKS under -s[0], using public switching keys.
// The refreshed ciphertext can be represented again as a k-component MLWR row
// with zero components 2..k. This is a same-ring bridge, never a ring switch.
struct BootstrapOptions {
    uint32_t n = 65536, slots = 8, scale_bits = 55, first_bits = 56;
    uint32_t security_bits = 128, usable_levels = 4;
    uint32_t cts_levels = 1, stc_levels = 1, large_digits = 3;
    uint32_t correction_factor = 0;
    bool flexible_scaling = true;
    uint32_t module_gadget_bits = 30;
    bool paper_sparse = false;
    bool project_repeated = true;
};
struct BootstrapProfile {
    Profile module;
    BootstrapOptions requested;
    uint32_t bootstrap_depth = 0, public_bits = 0, required_n = 0;
};
BootstrapProfile MakeBootstrapProfile(const BootstrapOptions&);
void WriteBootstrapProfile(std::ostream&, const BootstrapProfile&);

struct BootstrapKey {
    std::vector<lbcrypto::EvalKey<RingPoly>> folding;
    std::vector<std::string> source_tags;
    std::string native_tag;
    uint64_t context = 0, key_tag = 0;
    uint32_t k = 0;
};

class BootstrapBridge {
  public:
    BootstrapBridge(const ResearchScheme&, const BootstrapProfile&);
    BootstrapKey KeyGen(const SecretKey&) const;
    lbcrypto::Ciphertext<RingPoly> Fold(const Ciphertext&, const BootstrapKey&) const;
    Ciphertext Import(const lbcrypto::Ciphertext<RingPoly>&, const BootstrapKey&,
                      double public_bound) const;
    Ciphertext Refresh(const Ciphertext&, const BootstrapKey&, uint32_t iterations = 1,
                       uint32_t correction_precision = 0,
                       std::map<std::string,double>* timings = nullptr) const;
    // Explicit alternative evaluation backend after public folding. The factor
    // remains encrypted; its folding can be amortized across repeated uses.
    Ciphertext HybridMultiply(const Ciphertext&, const lbcrypto::Ciphertext<RingPoly>& factor,
                              const BootstrapKey&, double factor_bound,
                              std::map<std::string,double>* timings = nullptr) const;
    lbcrypto::Ciphertext<RingPoly> ProjectRepeated(const lbcrypto::Ciphertext<RingPoly>&) const;
  private:
    const ResearchScheme& scheme_;
    BootstrapProfile profile_;
    void Validate(const Ciphertext&, const BootstrapKey&) const;
};
}  // namespace mlwr
