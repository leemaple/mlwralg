#include "mlwr/scheme.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {
using namespace mlwr;
using Clock = std::chrono::steady_clock;
// Declared before running: approximately the previous 1e-6 acceptance target,
// now an exact binary precision target. This is NOT log2(encoding scale).
constexpr unsigned target_bits = 20;
constexpr double tolerance = 0x1p-20;
volatile uint64_t observed = 0;
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
double Norm(const RingPoly& poly, bool one = false) {
    double result = 0;
    const auto q = poly.GetParams()->GetModulus();
    for (const auto& x : Coefficients(poly)) {
        const double y = (x > (q >> 1) ? q - x : x).ConvertToDouble();
        result = one ? result + y : std::max(result, y);
    }
    return result;
}
Slots Pointwise(const Slots& a, const Slots& b, bool add = false) {
    Slots out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) out[i] = add ? a[i] + b[i] : a[i] * b[i];
    return out;
}
Slots Shift(const Slots& a) {
    Slots out(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) out[i] = a[(i + 1) % a.size()];
    return out;
}
double Error(const Slots& actual, const Slots& expected) {
    Require(actual.size() == expected.size(), "Slot count mismatch");
    double error = 0;
    for (std::size_t i = 0; i < actual.size(); ++i) {
        Require(std::isfinite(actual[i].real()) && std::isfinite(actual[i].imag()), "Nonfinite output");
        error = std::max(error, std::abs(actual[i] - expected[i]));
    }
    return error;
}
void Values(std::ostream& out, const Slots& values) {
    out << '[';
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) out << ',';
        out << '[' << values[i].real() << ',' << values[i].imag() << ']';
    }
    out << ']';
}
void Metric(std::ostream& out, const char* name, const Slots& actual,
            const Slots& expected, double scale, uint32_t level) {
    const auto error = Error(actual, expected);
    Require(error <= tolerance, "Decoded error exceeds the predeclared 20-bit target");
    out << "{\"operation\":\"" << name << "\",\"level\":" << level
        << ",\"scale\":" << scale << ",\"log2_scale\":" << std::log2(scale)
        << ",\"inverse_scale\":" << 1 / scale << ",\"max_absolute_error\":" << error
        << ",\"error_times_scale\":" << error * scale << ",\"precision_bits\":";
    if (error == 0) out << "null"; else out << -std::log2(error);
    out << ",\"passes_precision_target\":true,\"passes_inverse_scale\":"
        << (error <= 1 / scale ? "true" : "false") << ",\"expected\":";
    Values(out, expected);
    out << ",\"actual\":";
    Values(out, actual);
    out << ",\"slot_absolute_errors\":[";
    for (std::size_t i = 0; i < actual.size(); ++i) {
        if (i) out << ',';
        out << std::abs(actual[i] - expected[i]);
    }
    out << "]}";
}
void BasisJson(std::ostream& out, const RnsParams& basis) {
    out << "{\"modulus\":\"" << basis->GetModulus() << "\",\"bit_length\":"
        << basis->GetModulus().GetMSB() << ",\"log2_modulus\":"
        << std::log2(basis->GetModulus().ConvertToDouble()) << ",\"primes\":[";
    for (std::size_t i = 0; i < basis->GetParams().size(); ++i) {
        if (i) out << ',';
        out << '\"' << basis->GetParams()[i]->GetModulus() << '\"';
    }
    out << "]}";
}

void Correctness(std::ostream& out, const ResearchScheme& scheme) {
    const Slots reals{-1.25, -.125, 0, .125, .5, 1, 1.25, 2};
    const Slots factors{.5, -.25, 1.5, -1, .125, .75, -1.25, .5};
    const Slots complex{{.25,.125}, {-.5,.25}, {0,0}, {.125,-.0625},
                        {.5,-.5}, {1,.25}, {-.25,-.5}, {1.5,.125}};
    const Slots complex_factors{{-.5,.25}, {.25,-.5}, {1,.25}, {-.125,.5},
                                {.5,.5}, {-.25,.125}, {.25,1}, {.5,-.25}};
    std::mt19937 generator(20261013);  // Public messages only; never secret-key randomness.
    std::uniform_int_distribution<int> draw(-1024, 1024);
    out << '[';
    bool first = true;
    for (unsigned trial = 0; trial < 3; ++trial) {
        std::cerr << "Correctness: fresh key trial " << trial + 1 << "/3\n";
        const auto keys = scheme.KeyGen();
        const auto relin = scheme.RelinGen(keys.secret_key);
        double rounding_bound = .5;
        for (const auto& s : keys.secret_key.s) rounding_bound += .5 * Norm(s, true);
        const double fresh_bound = rounding_bound * (1 + 2.0 * scheme.profile().ciphertext->GetRingDimension() *
            scheme.basis(0)->GetModulus().ConvertToDouble() / scheme.public_basis()->GetModulus().ConvertToDouble());
        for (unsigned example = 0; example < 3; ++example) {
            Slots x = example == 0 ? reals : complex;
            Slots y = example == 0 ? factors : complex_factors;
            if (example == 2) for (unsigned i = 0; i < x.size(); ++i) {
                x[i] = {draw(generator) / 1024., draw(generator) / 1024.};
                y[i] = {draw(generator) / 1024., draw(generator) / 1024.};
            }
            const auto px = scheme.Encode(x), py = scheme.Encode(y);
            const auto cx = scheme.Encrypt(keys.public_key, px), cy = scheme.Encrypt(keys.public_key, py);
            const double fresh_x_noise = Norm(scheme.Phase(keys.secret_key, cx) - px.polynomial);
            const double fresh_y_noise = Norm(scheme.Phase(keys.secret_key, cy) - py.polynomial);
            Require(fresh_x_noise <= fresh_bound && fresh_y_noise <= fresh_bound, "Fresh coefficient noise bound");
            // FLEXIBLEAUTOEXT preparation is recorded separately from the
            // THREE multiplication stages; both inputs are now at level 1.
            const auto a = scheme.Rescale(cx), b = scheme.Rescale(cy);
            const auto tensor = scheme.Tensor(a, b);
            auto tensor_phase = tensor.linear[0];
            const auto s0 = SelectBasis(keys.secret_key.s[0], scheme.basis(a.level));
            const auto s1 = SelectBasis(keys.secret_key.s[1], scheme.basis(a.level));
            tensor_phase -= tensor.linear[1] * s0 + tensor.linear[2] * s1;
            tensor_phase += tensor.quadratic[0] * s0 * s0 + tensor.quadratic[1] * s0 * s1
                          + tensor.quadratic[2] * s1 * s0 + tensor.quadratic[3] * s1 * s1;
            const auto expected_phase = scheme.Phase(keys.secret_key, a) * scheme.Phase(keys.secret_key, b);
            Require(tensor_phase == expected_phase, "Tensor phase identity failed");
            const auto relinearized = scheme.Relinearize(tensor, relin);
            const double relin_noise = Norm(scheme.Phase(keys.secret_key, relinearized) - expected_phase);
            const double relin_bound = rounding_bound * (1 + 4.0 * scheme.profile().ciphertext->GetRingDimension() *
                scheme.basis(a.level)->GetModulus().ConvertToDouble() /
                (2 * scheme.profile().auxiliary->GetModulus().ConvertToDouble()));
            Require(relin_noise <= relin_bound, "Relinearization coefficient noise bound");
            const auto product = scheme.Rescale(relinearized);
            const double rescale_noise = Norm(scheme.Phase(keys.secret_key, product) -
                ScaleAndRound(scheme.Phase(keys.secret_key, relinearized), scheme.basis(product.level)));
            Require(rescale_noise <= rounding_bound + .5, "Rescale coefficient noise bound");
            if (!first) out << ',';
            first = false;
            out << "{\"trial\":" << trial + 1 << ",\"case\":\""
                << (example == 0 ? "real" : example == 1 ? "complex" : "dyadic_random") << "\",\"metrics\":[";
            Metric(out, "decode_encode_a", scheme.Decode(px), x, px.scale, px.level); out << ',';
            Metric(out, "decrypt_fresh_a", scheme.Decrypt(keys.secret_key, cx), x, cx.scale, cx.level); out << ',';
            Metric(out, "decrypt_fresh_b", scheme.Decrypt(keys.secret_key, cy), y, cy.scale, cy.level); out << ',';
            Metric(out, "decrypt_prepared_a", scheme.Decrypt(keys.secret_key, a), x, a.scale, a.level); out << ',';
            Metric(out, "decrypt_prepared_b", scheme.Decrypt(keys.secret_key, b), y, b.scale, b.level); out << ',';
            const auto expected = Pointwise(x, y);
            Metric(out, "multiply_before_rescale", scheme.Decrypt(keys.secret_key, relinearized), expected,
                   relinearized.scale, relinearized.level); out << ',';
            Metric(out, "multiply_after_rescale", scheme.Decrypt(keys.secret_key, product), expected,
                   product.scale, product.level);
            out << "],\"coefficient_checks\":{\"tensor_identity\":true,\"fresh_a\":" << fresh_x_noise
                << ",\"fresh_b\":" << fresh_y_noise << ",\"fresh_bound\":" << fresh_bound
                << ",\"relinearize\":" << relin_noise << ",\"relinearize_bound\":" << relin_bound
                << ",\"rescale\":" << rescale_noise << ",\"rescale_bound\":" << rounding_bound + .5
                << ",\"all_passed\":true}}";
        }
    }
    out << ']';
}

using Measurements = std::map<std::string, std::vector<double>>;
double Milliseconds(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}
template<class Operation, class Verify>
void Measure(Measurements& results, const std::string& name, unsigned warmups, unsigned samples,
             Operation operation, Verify verify) {
    std::cerr << "Timing: " << name << '\n';
    for (unsigned i = 0; i < warmups + samples; ++i) {
        const auto start = Clock::now();
        const auto result = operation();
        const auto end = Clock::now();
        verify(result);  // Decryption, comparison and reporting are outside the measured interval.
        if (i >= warmups) results[name].push_back(Milliseconds(start, end));
    }
}
void Benchmark(std::ostream& out, const ResearchScheme& scheme, unsigned samples, unsigned warmups) {
    const Slots x{-.75, -.125, 0, .125, .5, 1, 1.25, 1.5};
    const Slots y{.5, -.25, 1.5, -1, .125, .75, -1.25, .5};
    const auto keys = scheme.KeyGen();
    const auto relin = scheme.RelinGen(keys.secret_key);
    const auto rotation = scheme.RotateKeyGen(keys.secret_key, 1);
    const auto plaintext = scheme.Encode(x);
    const auto fresh = scheme.Encrypt(keys.public_key, plaintext);
    const auto a = scheme.Rescale(fresh);
    const auto b = scheme.Rescale(scheme.Encrypt(keys.public_key, y));
    const auto product = scheme.Rescale(scheme.Mult(a, b, relin));
    Measurements results;
    auto verify_slots = [&](const Slots& actual, const Slots& expected) {
        Require(Error(actual, expected) <= tolerance, "Timing sample correctness failed");
    };
    Measure(results, "keygen", warmups, samples, [&] { return scheme.KeyGen(); }, [&](const KeyPair& v) {
        verify_slots(scheme.Decrypt(v.secret_key, scheme.Encrypt(v.public_key, plaintext)), x);
    });
    Measure(results, "relin_keygen", warmups, samples, [&] { return scheme.RelinGen(keys.secret_key); },
        [&](const RelinearizationKey& v) { observed += v.key_tag; });
    Measure(results, "rotation_keygen", warmups, samples, [&] { return scheme.RotateKeyGen(keys.secret_key, 1); },
        [&](const RotationKey& v) { observed += v.exponent; });
    Measure(results, "encode", warmups, samples, [&] { return scheme.Encode(x); },
        [&](const Plaintext& v) { verify_slots(scheme.Decode(v), x); });
    Measure(results, "encrypt_preencoded", warmups, samples, [&] { return scheme.Encrypt(keys.public_key, plaintext); },
        [&](const Ciphertext& v) { verify_slots(scheme.Decrypt(keys.secret_key, v), x); });
    Measure(results, "decrypt_decode_fresh", warmups, samples, [&] { return scheme.Decrypt(keys.secret_key, fresh); },
        [&](const Slots& v) { verify_slots(v, x); });
    Measure(results, "prepare_one_ciphertext", warmups, samples, [&] { return scheme.Rescale(fresh); },
        [&](const Ciphertext& v) { verify_slots(scheme.Decrypt(keys.secret_key, v), x); });
    Measure(results, "add", warmups, samples, [&] { return scheme.Add(a, b); },
        [&](const Ciphertext& v) { verify_slots(scheme.Decrypt(keys.secret_key, v), Pointwise(x, y, true)); });
    Measure(results, "rotate_left_one", warmups, samples, [&] { return scheme.Rotate(a, rotation); },
        [&](const Ciphertext& v) { verify_slots(scheme.Decrypt(keys.secret_key, v), Shift(x)); });
    Measure(results, "decrypt_decode_product", warmups, samples, [&] { return scheme.Decrypt(keys.secret_key, product); },
        [&](const Slots& v) { verify_slots(v, Pointwise(x, y)); });
    std::cerr << "Timing: tensor -> relinearize -> rescale, same invocation\n";
    for (unsigned i = 0; i < warmups + samples; ++i) {
        const auto t0 = Clock::now();
        const auto tensor = scheme.Tensor(a, b);
        const auto t1 = Clock::now();
        const auto relinearized = scheme.Relinearize(tensor, relin);
        const auto t2 = Clock::now();
        const auto scaled = scheme.Rescale(relinearized);
        const auto t3 = Clock::now();
        verify_slots(scheme.Decrypt(keys.secret_key, scaled), Pointwise(x, y));
        if (i >= warmups) {
            results["multiply_tensor"].push_back(Milliseconds(t0, t1));
            results["multiply_relinearize"].push_back(Milliseconds(t1, t2));
            results["multiply_rescale"].push_back(Milliseconds(t2, t3));
            results["multiply_total"].push_back(Milliseconds(t0, t3));
        }
    }
    out << '{';
    bool first = true;
    for (const auto& item : results) {
        if (!first) out << ',';
        first = false;
        auto sorted = item.second;
        std::sort(sorted.begin(), sorted.end());
        const double mean = std::accumulate(sorted.begin(), sorted.end(), 0.) / sorted.size();
        double variance = 0;
        for (const auto x : sorted) variance += (x - mean) * (x - mean);
        const double median = sorted.size() % 2 ? sorted[sorted.size() / 2] :
            .5 * (sorted[sorted.size() / 2 - 1] + sorted[sorted.size() / 2]);
        out << '\"' << item.first << "\":{\"mean_ms\":" << mean << ",\"median_ms\":" << median
            << ",\"min_ms\":" << sorted.front() << ",\"max_ms\":" << sorted.back()
            << ",\"stddev_sample_ms\":" << std::sqrt(variance / (sorted.size() - 1))
            << ",\"p95_nearest_rank_ms\":" << sorted[std::size_t(std::ceil(.95 * sorted.size())) - 1]
            << ",\"samples_ms\":[";
        for (std::size_t i = 0; i < item.second.size(); ++i) {
            if (i) out << ',';
            out << item.second[i];
        }
        out << "]}";
    }
    out << '}';
}
}  // namespace

int main(int argc, char** argv) {
    try {
        const unsigned samples = argc > 1 ? std::stoul(argv[1]) : 15;
        const unsigned warmups = argc > 2 ? std::stoul(argv[2]) : 2;
        Require(argc <= 3 && samples >= 3 && samples <= 1000 && warmups >= 1 && warmups <= 100,
                "Usage: mlwr_experiment [samples 3..1000] [warmups 1..100]");
        const ResearchScheme scheme;
        std::ostringstream report;
        report << std::setprecision(17) << "{\"schema_version\":1,\"algorithm\":\"revised research construction\","
            << "\"security\":\"unproven\",\"bootstrap\":false,\"l\":2,\"k\":2,\"profile\":";
        WriteProfileJson(report, scheme.profile());
        report << ",\"moduli\":{\"P_main\":"; BasisJson(report, scheme.basis(0));
        report << ",\"Q_auxiliary\":"; BasisJson(report, scheme.profile().auxiliary);
        report << ",\"T_public\":"; BasisJson(report, scheme.public_basis());
        report << ",\"W_source\":"; BasisJson(report, scheme.source_basis());
        report << "},\"protocol\":{\"precision_target_bits\":" << target_bits << ",\"absolute_tolerance\":"
            << tolerance << ",\"target_origin\":\"existing approximately 20-bit test criterion, not a meeting-specified delta\","
            << "\"fresh_key_trials\":3,\"cases_per_key\":3,\"samples_per_operation\":" << samples
            << ",\"warmups_per_operation\":" << warmups << ",\"clock\":\"steady_clock\","
            << "\"timing_unit\":\"milliseconds per call over 8 slots\",\"smudge_bound\":0},\"correctness\":";
        Correctness(report, scheme);
        std::cerr << "Correctness gate passed; beginning timed operations\n";
        report << ",\"timings\":";
        Benchmark(report, scheme, samples, warmups);
        report << ",\"all_correctness_checks_passed\":true}\n";
        std::cout << report.str();
    } catch (const std::exception& error) {
        std::cerr << "Experiment failed: " << error.what() << '\n';
        return 1;
    }
}
