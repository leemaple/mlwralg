#include "mlwr/scheme.hpp"
#include "math/dftransform.h"

#include <atomic>
#include <cmath>
#include <random>
#include <stdexcept>

namespace mlwr {
namespace {
std::atomic<uint64_t> next_id{1};
RingPoly Zero(const RnsParams& p) { return RingPoly(p, EVALUATION, true); }
RingPoly Uniform(const RnsParams& p) {
    RingPoly::DugType sampler;
    return RingPoly(sampler, p, EVALUATION);
}
RingPoly Ternary(const RnsParams& p) {
    RingPoly::TugType sampler;
    return RingPoly(sampler, p, EVALUATION);
}
void Polynomial(const RingPoly& poly, const RnsParams& params) {
    if (!SameBasis(poly.GetParams(), params) || poly.GetFormat() != EVALUATION)
        throw std::invalid_argument("Polynomial has incompatible RNS basis or format");
}
}  // namespace

ResearchScheme::ResearchScheme(Profile profile, uint32_t l, uint32_t k)
    : profile_(std::move(profile)), l_(l), k_(k), id_(next_id++) {
    if (profile_.compact) throw std::invalid_argument("Use CompactScheme for a compact profile");
    if (l_ < 1 || l_ > 8 || k_ < 1 || k_ > 8)
        throw std::invalid_argument("Supported module dimensions: l and k independently in 1..8");
    extended_ = JoinBases(profile_.ciphertext, profile_.auxiliary);
    public_ = IndependentLargerBasis(profile_.ciphertext, profile_.auxiliary);
    source_ = IndependentLargerBasis(extended_, public_);
    if (source_->GetModulus() <= public_->GetModulus())
        throw std::invalid_argument("Source modulus must exceed both rounding targets");
}

RnsParams ResearchScheme::basis(uint32_t level) const {
    const auto count = profile_.ciphertext->GetParams().size();
    if (level >= count) throw std::invalid_argument("Modulus chain exhausted");
    return PrefixBasis(profile_.ciphertext, count - level);
}

void ResearchScheme::Budget(uint32_t level, double scale, double bound) const {
    const auto p = basis(level);
    // This floating-point profile excludes nearly-unscaled ciphertexts: their
    // integer rounding noise would swamp the represented fractional values.
    if (!std::isfinite(scale) || scale < std::ldexp(1.0, 40) || !std::isfinite(bound) || bound <= 0 ||
        scale * (bound + 1) >= p->GetModulus().ConvertToDouble() / 2)
        throw std::invalid_argument("Scale or public message bound exceeds modulus budget");
}
void ResearchScheme::Validate(const SecretKey& key) const {
    if (key.context != id_ || !key.tag) throw std::invalid_argument("Wrong secret-key context");
    if (key.s.size() != k_) throw std::invalid_argument("Wrong secret-key dimension");
    for (const auto& s : key.s) Polynomial(s, profile_.ciphertext);
}
void ResearchScheme::Validate(const Ciphertext& value) const {
    if (value.context != id_ || !value.key_tag) throw std::invalid_argument("Wrong ciphertext context");
    if (value.c.size() != k_ + 1) throw std::invalid_argument("Wrong ciphertext dimension");
    Budget(value.level, value.scale, value.bound);
    for (const auto& c : value.c) Polynomial(c, basis(value.level));
}
void ResearchScheme::Validate(const Plaintext& value) const {
    if (value.context != id_) throw std::invalid_argument("Wrong plaintext context");
    Budget(value.level, value.scale, value.bound);
    Polynomial(value.polynomial, basis(value.level));
}
void ResearchScheme::ValidateRows(const std::vector<Row>& rows) const {
    for (const auto& row : rows) {
        if (row.size() != k_ + 1) throw std::invalid_argument("Wrong switching row dimension");
        for (const auto& poly : row) Polynomial(poly, extended_);
    }
}

Row ResearchScheme::MakeRow(const std::vector<RingPoly>& secret,
                             const RnsParams& target, const RingPoly* embedding) const {
    Row result(k_ + 1);
    auto inner = Zero(source_);
    for (std::size_t j = 0; j < k_; ++j) {
        auto a = Uniform(source_);
        inner += a * secret[j];
        result[j + 1] = ScaleAndRound(a, target);
    }
    result[0] = ScaleAndRound(inner, target);
    if (embedding) result[0] += *embedding;
    return result;
}

KeyPair ResearchScheme::KeyGen() const {
    KeyPair keys;
    keys.secret_key.s.resize(k_);
    keys.public_key.rows.resize(l_);
    keys.secret_key.context = keys.public_key.context = id_;
    keys.secret_key.tag = keys.public_key.tag = next_id++;
    std::vector<RingPoly> source_secret(k_);
    for (std::size_t j = 0; j < k_; ++j) {
        keys.secret_key.s[j] = Ternary(profile_.ciphertext);
        source_secret[j] = LiftCentered(keys.secret_key.s[j], source_);
    }
    for (auto& row : keys.public_key.rows) row = MakeRow(source_secret, public_);
    return keys;
}

RelinearizationKey ResearchScheme::RelinGen(const SecretKey& key) const {
    Validate(key);
    RelinearizationKey result;
    result.rows.resize(k_ * k_);
    result.context = id_;
    result.key_tag = key.tag;
    std::vector<RingPoly> source_secret(k_), extended_secret(k_);
    for (std::size_t j = 0; j < k_; ++j) {
        source_secret[j] = LiftCentered(key.s[j], source_);
        extended_secret[j] = LiftCentered(key.s[j], extended_);
    }
    for (std::size_t i = 0; i < k_; ++i) for (std::size_t j = 0; j < k_; ++j) {
        const auto embedding = MultiplyInteger(extended_secret[i] * extended_secret[j],
                                               profile_.auxiliary->GetModulus());
        result.rows[i * k_ + j] = MakeRow(source_secret, extended_, &embedding);
    }
    return result;
}

SwitchingKey ResearchScheme::KSGen(const SecretKey& target, const SecretKey& source) const {
    Validate(target);
    Validate(source);
    SwitchingKey result;
    result.rows.resize(k_);
    result.context = id_;
    result.source_tag = source.tag;
    result.target_tag = target.tag;
    std::vector<RingPoly> target_source(k_);
    for (std::size_t j = 0; j < k_; ++j) target_source[j] = LiftCentered(target.s[j], source_);
    for (std::size_t i = 0; i < k_; ++i) {
        const auto embedding = MultiplyInteger(LiftCentered(source.s[i], extended_),
                                               profile_.auxiliary->GetModulus());
        result.rows[i] = MakeRow(target_source, extended_, &embedding);
    }
    return result;
}

RotationKey ResearchScheme::RotateKeyGen(const SecretKey& key, int64_t steps) const {
    Validate(key);
    const auto exponent = RotationExponent(steps, profile_.ciphertext->GetRingDimension());
    auto transformed = key;
    for (auto& s : transformed.s) s = Automorphism(s, exponent);
    return {KSGen(key, transformed), exponent};
}

Plaintext ResearchScheme::Encode(const Slots& values, uint32_t level,
                                 double public_bound, double scale) const {
    if (values.empty() || values.size() > profile_.slots)
        throw std::invalid_argument("Invalid number of packed slots");
    for (auto z : values)
        if (!std::isfinite(z.real()) || !std::isfinite(z.imag()) || std::abs(z) > public_bound)
            throw std::invalid_argument("Input is non-finite or exceeds declared public bound");
    lbcrypto::Plaintext encoded;
    if (scale == 0) {
        encoded = profile_.encoder->MakeCKKSPackedPlaintext(values, 1, level, nullptr, profile_.slots);
    } else {
        Budget(level, scale, public_bound);
        encoded = std::make_shared<lbcrypto::CKKSPackedEncoding>(basis(level),
            profile_.encoder->GetEncodingParams(), values, 1, level, scale, profile_.slots, lbcrypto::COMPLEX);
        encoded->Encode();
    }
    Plaintext out{encoded->GetElement<RingPoly>(), encoded->GetScalingFactor(), public_bound, level, id_};
    Validate(out);
    return out;
}

Slots ResearchScheme::Decode(const Plaintext& plaintext) const {
    Validate(plaintext);
    const auto coefficients = Coefficients(plaintext.polynomial);
    const auto& modulus = plaintext.polynomial.GetParams()->GetModulus();
    const auto half = modulus >> 1;
    const std::size_t nh = coefficients.size() / 2;
    auto centered = [&](std::size_t i) {
        const auto& x = coefficients[i];
        return (x > half ? -(modulus - x).ConvertToDouble() : x.ConvertToDouble()) / plaintext.scale;
    };
    // Decode the entire canonical embedding, including noise outside the sparse
    // plaintext subring. Return the first slots of the repeated packed vector.
    Slots values(nh);
    for (std::size_t i = 0; i < nh; ++i) values[i] = {centered(i), centered(i + nh)};
    lbcrypto::DiscreteFourierTransform::FFTSpecial(values, profile_.ciphertext->GetCyclotomicOrder());
    values.resize(profile_.slots);
    for (auto z : values)
        if (!std::isfinite(z.real()) || !std::isfinite(z.imag())) throw std::runtime_error("Non-finite decode");
    return values;
}

Ciphertext ResearchScheme::Encrypt(const PublicKey& key, const Slots& message) const {
    return Encrypt(key, Encode(message));
}
Ciphertext ResearchScheme::Encrypt(const PublicKey& key, const Plaintext& message) const {
    Validate(message);
    if (message.level != 0 || key.context != id_ || !key.tag)
        throw std::invalid_argument("Encryption requires a fresh plaintext and matching public key");
    if (key.rows.size() != l_) throw std::invalid_argument("Wrong public-key row count");
    for (const auto& row : key.rows) {
        if (row.size() != k_ + 1) throw std::invalid_argument("Wrong public-key column count");
        for (const auto& a : row) Polynomial(a, public_);
    }
    std::vector<RingPoly> randomizer(l_);
    for (auto& r : randomizer) r = Ternary(public_);
    Ciphertext out;
    out.c.resize(k_ + 1);
    out.scale = message.scale;
    out.bound = message.bound;
    out.context = id_;
    out.key_tag = key.tag;
    for (std::size_t j = 0; j <= k_; ++j) {
        auto dot = Zero(public_);
        for (std::size_t i = 0; i < l_; ++i) dot += key.rows[i][j] * randomizer[i];
        out.c[j] = ScaleAndRound(dot, profile_.ciphertext);
    }
    out.c[0] += message.polynomial;
    return out;
}

RingPoly ResearchScheme::Phase(const SecretKey& key, const Ciphertext& ciphertext) const {
    Validate(key);
    Validate(ciphertext);
    if (key.tag != ciphertext.key_tag) throw std::invalid_argument("Wrong decryption key");
    auto out = ciphertext.c[0];
    for (std::size_t j = 0; j < k_; ++j)
        out -= ciphertext.c[j + 1] * SelectBasis(key.s[j], basis(ciphertext.level));
    return out;
}
Slots ResearchScheme::Decrypt(const SecretKey& key, const Ciphertext& ciphertext, uint32_t bound) const {
    auto phase = Phase(key, ciphertext);
    if (bound) {
        std::uniform_int_distribution<int64_t> distribution(-int64_t(bound), int64_t(bound));
        auto& generator = lbcrypto::PseudoRandomNumberGenerator::GetPRNG();
        std::vector<int64_t> noise(profile_.ciphertext->GetRingDimension());
        for (auto& x : noise) x = distribution(generator);
        phase += FromSignedCoefficients(basis(ciphertext.level), noise);
    }
    return Decode({phase, ciphertext.scale, ciphertext.bound, ciphertext.level, id_});
}

Ciphertext ResearchScheme::Add(const Ciphertext& a, const Ciphertext& b) const {
    Validate(a);
    Validate(b);
    if (a.key_tag != b.key_tag || a.level != b.level ||
        std::abs(a.scale / b.scale - 1) > 1e-12)
        throw std::invalid_argument("Addition requires the same key, level, and scale");
    auto out = a;
    out.bound += b.bound;
    Budget(out.level, out.scale, out.bound);
    for (std::size_t j = 0; j <= k_; ++j) out.c[j] += b.c[j];
    return out;
}
Ciphertext ResearchScheme::PlainMult(const Ciphertext& a, const Plaintext& b) const {
    Validate(a);
    Validate(b);
    if (a.level != b.level) throw std::invalid_argument("Plaintext multiplication requires matching levels");
    auto out = a;
    out.scale *= b.scale;
    out.bound *= b.bound;
    Budget(out.level, out.scale, out.bound);
    for (auto& component : out.c) component *= b.polynomial;
    return out;
}

Row ResearchScheme::SwitchProduct(const std::vector<RingPoly>& multipliers,
                                   const std::vector<Row>& rows, uint32_t level) const {
    if (multipliers.size() != rows.size()) throw std::invalid_argument("Switching row count mismatch");
    ValidateRows(rows);
    const auto p = basis(level);
    const auto pq = JoinBases(p, profile_.auxiliary);
    Row sum(k_ + 1, Zero(pq));
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const auto lifted = LiftCentered(multipliers[i], pq);
        for (std::size_t j = 0; j <= k_; ++j) sum[j] += lifted * SelectBasis(rows[i][j], pq);
    }
    for (auto& component : sum) component = ScaleAndRound(component, p);
    return sum;
}
TensorCiphertext ResearchScheme::Tensor(const Ciphertext& a, const Ciphertext& b) const {
    Validate(a);
    Validate(b);
    if (a.key_tag != b.key_tag || a.level != b.level)
        throw std::invalid_argument("Tensor product requires matching keys and levels");
    TensorCiphertext out;
    out.linear.resize(k_ + 1);
    out.quadratic.resize(k_ * k_);
    out.scale = a.scale * b.scale;
    out.bound = a.bound * b.bound;
    out.level = a.level;
    out.context = id_;
    out.key_tag = a.key_tag;
    Budget(out.level, out.scale, out.bound);
    out.linear[0] = a.c[0] * b.c[0];
    for (std::size_t j = 1; j <= k_; ++j) out.linear[j] = a.c[0] * b.c[j] + a.c[j] * b.c[0];
    for (std::size_t i = 1; i <= k_; ++i) for (std::size_t j = 1; j <= k_; ++j)
        out.quadratic[(i - 1) * k_ + j - 1] = a.c[i] * b.c[j];
    return out;
}
Ciphertext ResearchScheme::Relinearize(const TensorCiphertext& tensor,
                                      const RelinearizationKey& key) const {
    if (tensor.context != id_ || !tensor.key_tag || key.context != id_ || key.key_tag != tensor.key_tag)
        throw std::invalid_argument("Relinearization requires a matching tensor and key");
    if (tensor.linear.size() != k_ + 1 || tensor.quadratic.size() != k_ * k_ ||
        key.rows.size() != k_ * k_)
        throw std::invalid_argument("Wrong tensor or relinearization-key dimension");
    Budget(tensor.level, tensor.scale, tensor.bound);
    const auto p = basis(tensor.level);
    for (const auto& c : tensor.linear) Polynomial(c, p);
    for (const auto& c : tensor.quadratic) Polynomial(c, p);
    Ciphertext out{tensor.linear, tensor.scale, tensor.bound, tensor.level, id_, tensor.key_tag};
    auto switched = SwitchProduct({tensor.quadratic.begin(), tensor.quadratic.end()},
                                  key.rows, tensor.level);
    // sk = (1,-s); the quadratic contribution is POSITIVE. Source (5-3)
    // prints minus, which fails even for the noiseless constant example.
    for (std::size_t j = 0; j <= k_; ++j) out.c[j] += switched[j];
    return out;
}
Ciphertext ResearchScheme::Mult(const Ciphertext& a, const Ciphertext& b,
                                const RelinearizationKey& key) const {
    return Relinearize(Tensor(a, b), key);
}
Ciphertext ResearchScheme::Rescale(const Ciphertext& value, uint32_t dropped) const {
    Validate(value);
    if (!dropped || dropped >= basis(value.level)->GetParams().size())
        throw std::invalid_argument("Invalid rescale depth");
    auto out = value;
    out.level += dropped;
    const auto target = basis(out.level);
    const auto divisor = basis(value.level)->GetModulus() / target->GetModulus();
    out.scale /= divisor.ConvertToDouble();
    Budget(out.level, out.scale, out.bound);
    for (auto& component : out.c) component = ScaleAndRound(component, target);
    return out;
}
Ciphertext ResearchScheme::KeySwitch(const Ciphertext& value, const SwitchingKey& key) const {
    Validate(value);
    if (key.context != id_ || key.source_tag != value.key_tag || !key.target_tag)
        throw std::invalid_argument("Wrong switching key");
    if (key.rows.size() != k_) throw std::invalid_argument("Wrong switching-key row count");
    auto switched = SwitchProduct({value.c.begin() + 1, value.c.end()}, key.rows, value.level);
    auto out = value;
    out.key_tag = key.target_tag;
    out.c[0] -= switched[0];
    for (std::size_t j = 1; j <= k_; ++j) out.c[j] = Zero(basis(value.level)) - switched[j];
    return out;
}
Ciphertext ResearchScheme::Rotate(const Ciphertext& value, const RotationKey& key) const {
    Validate(value);
    if (key.switching.source_tag != key.switching.target_tag)
        throw std::invalid_argument("Rotation key must switch back to the original key");
    auto transformed = value;
    for (auto& component : transformed.c) component = Automorphism(component, key.exponent);
    return KeySwitch(transformed, key.switching);
}
}  // namespace mlwr
