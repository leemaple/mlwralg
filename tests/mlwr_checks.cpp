#include "mlwr/scheme.hpp"

#include <algorithm>
#include <cmath>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <stdexcept>
#include <string>

namespace {
using namespace mlwr;
std::map<std::string, double> errors;
unsigned checks = 0;
void Require(bool condition, const std::string& message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
void Reject(const std::function<void()>& operation, const std::string& name) {
    try { operation(); }
    catch (const std::invalid_argument&) { ++checks; return; }
    throw std::runtime_error("Invalid input accepted: " + name);
}
void Close(const std::string& name, const Slots& actual, const Slots& expected, double tolerance = 1e-6) {
    Require(actual.size() == expected.size(), name + " slot count mismatch");
    double error = 0;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        Require(std::isfinite(actual[i].real()) && std::isfinite(actual[i].imag()), name + " non-finite output");
        error = std::max(error, std::abs(actual[i] - expected[i]));
    }
    errors[name] = std::max(errors[name], error);
    Require(error <= tolerance, name + " error " + std::to_string(error) + " exceeds tolerance");
}
Slots Pointwise(const Slots& a, const Slots& b, bool add = false) {
    Slots result(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) result[i] = add ? a[i] + b[i] : a[i] * b[i];
    return result;
}
Slots RotateExpected(const Slots& values, int steps) {
    Slots result(values.size());
    const auto n = static_cast<int>(values.size());
    for (int i = 0; i < n; ++i) result[i] = values[(i + steps % n + n) % n];
    return result;
}
double Norm(const RingPoly& poly, bool one = false) {
    double result = 0;
    const auto& q = poly.GetParams()->GetModulus();
    for (const auto& x : Coefficients(poly)) {
        double abs = (x > (q >> 1) ? q - x : x).ConvertToDouble();
        result = one ? result + abs : std::max(result, abs);
    }
    return result;
}
RingPoly RowPhase(const Row& row, const SecretKey& secret) {
    auto phase = row[0];
    for (std::size_t i = 0; i < k; ++i) phase -= row[i + 1] * LiftCentered(secret.s[i], phase.GetParams());
    return phase;
}
void KeyErrors(const ResearchScheme& scheme, const KeyPair& keys, const RelinearizationKey& relin) {
    double bs = .5;
    for (const auto& s : keys.secret_key.s) bs += .5 * Norm(s, true);
    for (const auto& row : keys.public_key.rows)
        Require(Norm(RowPhase(row, keys.secret_key)) <= bs, "Public key rounding noise bound");
    const auto pq = JoinBases(scheme.profile().ciphertext, scheme.profile().auxiliary);
    for (std::size_t i = 0; i < k; ++i) for (std::size_t j = 0; j < k; ++j) {
        const auto target = MultiplyInteger(LiftCentered(keys.secret_key.s[i], pq) *
            LiftCentered(keys.secret_key.s[j], pq), scheme.profile().auxiliary->GetModulus());
        Require(Norm(RowPhase(relin.rows[i * k + j], keys.secret_key) - target) <= bs,
                "Tensor row or evaluation-key noise bound");
    }
}

void Trial(const ResearchScheme& scheme, const Slots& values, const Slots& factors, unsigned index) {
    std::cerr << "MLWR trial " << index + 1 << ": key generation\n";
    const auto keys = scheme.KeyGen();
    const auto relin = scheme.RelinGen(keys.secret_key);
    KeyErrors(scheme, keys, relin);
    const auto encoded = scheme.Encode(values);
    Close("encoding", scheme.Decode(encoded), values);
    const auto fresh = scheme.Encrypt(keys.public_key, encoded);
    Close("fresh_encryption", scheme.Decrypt(keys.secret_key, fresh), values);
    const auto fresh2 = scheme.Encrypt(keys.public_key, encoded);
    Require(fresh.c[0] != fresh2.c[0] || fresh.c[1] != fresh2.c[1] || fresh.c[2] != fresh2.c[2],
            "Encryption randomness reused");
    double bs = .5;
    for (const auto& s : keys.secret_key.s) bs += .5 * Norm(s, true);
    const double fresh_bound = bs * (1 + 2.0 * scheme.profile().ciphertext->GetRingDimension() *
        scheme.profile().ciphertext->GetModulus().ConvertToDouble() / scheme.public_basis()->GetModulus().ConvertToDouble());
    Require(Norm(scheme.Phase(keys.secret_key, fresh) - encoded.polynomial) <= fresh_bound,
            "Fresh ciphertext phase exceeds exact rounding bound");
    Close("uniform_flooding_1024", scheme.Decrypt(keys.secret_key, fresh, 1024), values);

    // FLEXIBLEAUTOEXT's initial extra tower is removed explicitly, retaining the
    // ACTUAL encoder scale divided by that prime, rather than assuming 2^50.
    const auto a = scheme.Rescale(fresh);
    const auto b = scheme.Rescale(scheme.Encrypt(keys.public_key, factors));
    Close("initial_rescale", scheme.Decrypt(keys.secret_key, a), values);
    Reject([&] { scheme.Rescale(a); }, "premature extra rescale loses precision");
    Reject([&] { scheme.Encode(values, 1, 2, 1); }, "insufficient encoding scale");
    const auto phase_rounded = ScaleAndRound(scheme.Phase(keys.secret_key, fresh), scheme.basis(1));
    Require(Norm(scheme.Phase(keys.secret_key, a) - phase_rounded) <= bs + .5,
            "Rescaling phase discrepancy exceeds bound");
    Close("addition", scheme.Decrypt(keys.secret_key, scheme.Add(a, b)), Pointwise(values, factors, true));
    const auto plain_product = scheme.PlainMult(a, scheme.Encode(factors, a.level));
    Close("plaintext_multiplication", scheme.Decrypt(keys.secret_key, plain_product), Pointwise(values, factors));
    Close("plaintext_multiplication_rescaled", scheme.Decrypt(keys.secret_key, scheme.Rescale(plain_product)),
          Pointwise(values, factors));

    std::cerr << "MLWR trial " << index + 1 << ": multiplication, switching, rotation\n";
    const auto raw_product = scheme.Mult(a, b, relin);
    const auto tensor = scheme.Tensor(a, b);
    const auto staged_product = scheme.Relinearize(tensor, relin);
    for (std::size_t i = 0; i <= k; ++i)
        Require(staged_product.c[i] == raw_product.c[i], "Staged and combined multiplication differ");
    auto bad_tensor = tensor;
    bad_tensor.key_tag = 0;
    Reject([&] { scheme.Relinearize(bad_tensor, relin); }, "tensor without key identity");
    bad_tensor = tensor;
    bad_tensor.quadratic[0] = fresh.c[0];
    Reject([&] { scheme.Relinearize(bad_tensor, relin); }, "tensor with wrong quadratic basis");
    Close("ciphertext_multiplication", scheme.Decrypt(keys.secret_key, raw_product), Pointwise(values, factors));
    const auto phase_product = scheme.Phase(keys.secret_key, a) * scheme.Phase(keys.secret_key, b);
    const double p = scheme.basis(a.level)->GetModulus().ConvertToDouble();
    const double q = scheme.profile().auxiliary->GetModulus().ConvertToDouble();
    const double relin_bound = bs * (1 + 4.0 * scheme.profile().ciphertext->GetRingDimension() * p / (2 * q));
    Require(Norm(scheme.Phase(keys.secret_key, raw_product) - phase_product) <= relin_bound,
            "Relinearization phase or noise bound failed");

    auto power = a;
    auto expected = values;
    for (unsigned depth = 1; depth <= 3; ++depth) {
        power = scheme.Rescale(scheme.Mult(power, power, relin));
        expected = Pointwise(expected, expected);
        Close("power_depth_" + std::to_string(depth), scheme.Decrypt(keys.secret_key, power), expected);
    }
    Reject([&] { scheme.Rescale(power); }, "exhausted chain");
    Reject([&] { scheme.Mult(power, power, relin); }, "scale overflow");

    const auto other = scheme.KeyGen();
    const auto switching = scheme.KSGen(other.secret_key, keys.secret_key);
    Close("key_switch", scheme.Decrypt(other.secret_key, scheme.KeySwitch(a, switching)), values);
    Close("key_switch_last_level", scheme.Decrypt(other.secret_key, scheme.KeySwitch(power, switching)), expected);
    Reject([&] { scheme.Decrypt(other.secret_key, a); }, "wrong secret key");
    Reject([&] { scheme.KeySwitch(scheme.KeySwitch(a, switching), switching); }, "wrong source key");

    for (int shift : {-1, 1, 3, 8}) {
        const auto rotation = scheme.RotateKeyGen(keys.secret_key, shift);
        Close("rotation_" + std::to_string(shift), scheme.Decrypt(keys.secret_key, scheme.Rotate(a, rotation)),
              RotateExpected(values, shift));
        if (shift == 1)
            Close("rotation_last_level", scheme.Decrypt(keys.secret_key, scheme.Rotate(power, rotation)),
                  RotateExpected(expected, shift));
    }

    Reject([&] { scheme.Add(a, fresh); }, "mixed levels");
    Reject([&] { scheme.Mult(a, fresh, relin); }, "mixed multiplication levels");
    Reject([&] { scheme.PlainMult(a, encoded); }, "mixed plaintext level");
    Reject([&] { scheme.Encrypt(keys.public_key, scheme.Encode(values, 1)); }, "nonfresh plaintext");
    auto malformed = a;
    malformed.scale *= 2;
    Reject([&] { scheme.Add(a, malformed); }, "mixed scales");
    malformed = a;
    malformed.c[1] = fresh.c[1];
    Reject([&] { scheme.Decrypt(keys.secret_key, malformed); }, "malformed RNS basis");
    Reject([&] { scheme.Encode({{std::numeric_limits<double>::quiet_NaN(), 0}}); }, "NaN");
    Reject([&] { scheme.Encode({{3, 0}}); }, "undeclared input magnitude");
    Reject([&] { scheme.Encode(Slots(9)); }, "too many slots");
}
void FullPacking() {
    const auto preliminary = OpenFheProfile(1, 8);
    const auto slots = preliminary.ciphertext->GetRingDimension() / 2;
    ResearchScheme scheme(OpenFheProfile(1, slots));
    Slots values(slots);
    for (std::size_t i = 0; i < slots; ++i)
        values[i] = {.125 * (int(i % 9) - 4), .0625 * (int(i % 7) - 3)};
    const auto keys = scheme.KeyGen();
    const auto ciphertext = scheme.Encrypt(keys.public_key, values);
    Close("full_packing", scheme.Decrypt(keys.secret_key, ciphertext), values);
    const auto rotation = scheme.RotateKeyGen(keys.secret_key, -1);
    Close("full_packing_rotation", scheme.Decrypt(keys.secret_key, scheme.Rotate(ciphertext, rotation)),
          RotateExpected(values, -1));
}
void WriteBasis(const RnsParams& basis) {
    std::cout << '[';
    for (std::size_t i = 0; i < basis->GetParams().size(); ++i) {
        if (i) std::cout << ',';
        std::cout << '"' << basis->GetParams()[i]->GetModulus() << '"';
    }
    std::cout << ']';
}
}  // namespace

int main() {
    try {
        ResearchScheme scheme;
        const Slots first{{-1.25, 0}, {-.125, 0}, {0, 0}, {.125, 0}, {.5, 0}, {1, 0}, {1.25, 0}, {2, 0}};
        const Slots second{{.25, .125}, {-.5, .25}, {0, 0}, {1e-6, -1e-6}, {.5, -.5}, {1, .25}, {-.25, -.5}, {1.5, 0}};
        Trial(scheme, first, second, 0);
        Trial(scheme, second, first, 1);
        std::mt19937_64 rng(20261012); // Public test INPUTS only; cryptographic sampling uses OpenFHE PRNG.
        std::uniform_real_distribution<double> distribution(-1, 1);
        Slots random(8), factors(8);
        for (auto& z : random) z = {distribution(rng), distribution(rng)};
        for (auto& z : factors) z = {distribution(rng), distribution(rng)};
        Trial(scheme, random, factors, 2);
        const auto keys = scheme.KeyGen();
        const auto zero = scheme.Encrypt(keys.public_key, Slots(8));
        Close("zero", scheme.Decrypt(keys.secret_key, zero), Slots(8));
        const auto partial = scheme.Encrypt(keys.public_key, Slots{{.125, -.25}});
        Slots padded(8); padded[0] = {.125, -.25};
        Close("zero_padding", scheme.Decrypt(keys.secret_key, partial), padded);
        ResearchScheme separate(scheme.profile());
        Reject([&] { separate.Decrypt(keys.secret_key, zero); }, "different context");
        FullPacking();
        std::cout << std::setprecision(17) << "{\n\"scheme\":\"MLWR revised research construction\",\n"
                  << "\"security_status\":\"unproven\",\n\"bootstrap\":false,\n\"l\":2,\"k\":2,\n\"profile\":";
        WriteProfileJson(std::cout, scheme.profile());
        std::cout << ",\n\"public_modulus_primes\":";
        WriteBasis(scheme.public_basis());
        std::cout << ",\n\"source_modulus_primes\":";
        WriteBasis(scheme.source_basis());
        std::cout << ",\n\"fresh_key_trials\":3,\n\"checks\":" << checks << ",\n\"absolute_tolerance\":1e-6,"
                  << "\n\"max_absolute_error\":{";
        bool first_error = true;
        for (const auto& [name, error] : errors) {
            if (!first_error) std::cout << ',';
            first_error = false;
            std::cout << '\n' << '"' << name << "\":" << error;
        }
        std::cout << "\n}\n}\n";
    } catch (const std::exception& error) {
        std::cerr << "MLWR checks failed: " << error.what() << '\n';
        return 1;
    }
}
