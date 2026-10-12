#include "mlwr/scheme.hpp"
#include <iomanip>
#include <iostream>

int main() {
    try {
        mlwr::ResearchScheme scheme;
        const auto keys = scheme.KeyGen();
        const auto relin = scheme.RelinGen(keys.secret_key);
        const auto rotate = scheme.RotateKeyGen(keys.secret_key, 1);
        const mlwr::Slots input{{-.5, .25}, {0, 0}, {.125, 0}, {.25, -.25}, {.5, 0}, {1, 0}, {1.5, 0}, {2, 0}};
        const auto encrypted = scheme.Rescale(scheme.Encrypt(keys.public_key, input));
        const auto squared = scheme.Rescale(scheme.Mult(encrypted, encrypted, relin));
        const auto shifted = scheme.Rotate(squared, rotate);
        const auto output = scheme.Decrypt(keys.secret_key, shifted);
        std::cout << "MLWR revised research construction: l=k=2; security unproven; no bootstrap\n"
                  << "Circuit: rotate_left(square(input), 1)\n" << std::setprecision(12);
        for (std::size_t i = 0; i < output.size(); ++i) {
            const auto x = input[(i + 1) % input.size()];
            std::cout << i << ": actual=" << output[i] << " expected=" << x * x
                      << " error=" << std::abs(output[i] - x * x) << '\n';
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
