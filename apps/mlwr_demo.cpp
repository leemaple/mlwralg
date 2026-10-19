#include "mlwr/scheme.hpp"
#include "mlwr/options.hpp"
#include <iomanip>
#include <iostream>

int main(int argc, char** argv) {
    try {
        const auto options = mlwr::ParseOptions(argc, argv);
        if (options.help) { mlwr::PrintOptionsHelp(std::cout); return 0; }
        mlwr::ResearchScheme scheme(options.MakeProfile(), options.l, options.k);
        if (options.print_parameters) {
            std::cout << "{\"requested_parameters\":";
            mlwr::WriteOptionsJson(std::cout, options);
            std::cout << ",\"profile\":";
            mlwr::WriteProfileJson(std::cout, scheme.profile());
            std::cout << "}\n";
            return 0;
        }
        const auto keys = scheme.KeyGen();
        const auto relin = scheme.RelinGen(keys.secret_key);
        const auto rotate = scheme.RotateKeyGen(keys.secret_key, options.rotation_steps);
        const mlwr::Slots pattern{{-.5, .25}, {0, 0}, {.125, 0}, {.25, -.25}, {.5, 0}, {1, 0}, {1.5, 0}, {2, 0}};
        mlwr::Slots input(scheme.profile().slots);
        for (std::size_t i = 0; i < input.size(); ++i) input[i] = pattern[i % pattern.size()] * (options.message_bound / 2);
        const auto encrypted = scheme.Rescale(scheme.Encrypt(keys.public_key, scheme.Encode(input, 0, options.message_bound, options.EncodingScale())));
        const auto squared = scheme.Rescale(scheme.Mult(encrypted, encrypted, relin));
        const auto shifted = scheme.Rotate(squared, rotate);
        const auto output = scheme.Decrypt(keys.secret_key, shifted, options.smudge_bound);
        std::cout << "MLWR revised research construction: l=" << scheme.l() << " k=" << scheme.k()
                  << " N=" << scheme.profile().ciphertext->GetRingDimension()
                  << "; security unproven; no bootstrap\n"
                  << "Circuit: rotate(square(input), " << options.rotation_steps << ")\n" << std::setprecision(12);
        for (std::size_t i = 0; i < output.size(); ++i) {
            const auto x = input[(int64_t(i) + options.rotation_steps % int64_t(input.size()) + int64_t(input.size())) % input.size()];
            if (std::abs(output[i] - x * x) > std::ldexp(1.0, -int(options.precision_bits)))
                throw std::runtime_error("Demo output exceeds the configured precision target");
            std::cout << i << ": actual=" << output[i] << " expected=" << x * x
                      << " error=" << std::abs(output[i] - x * x) << '\n';
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
