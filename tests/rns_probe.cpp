#include "mlwr/rns.hpp"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        try {
            std::istringstream input(line);
            std::string operation;
            uint32_t n;
            std::size_t source_count, target_count;
            int64_t steps;
            input >> operation >> n >> source_count >> target_count >> steps;
            if (!input || n > 1024 || source_count > 32 || target_count > 32) {
                throw std::invalid_argument("Invalid probe dimensions");
            }
            std::vector<uint64_t> source(source_count), target(target_count);
            for (auto& x : source) input >> x;
            for (auto& x : target) input >> x;
            std::vector<mlwr::Integer> a, b;
            for (uint32_t i = 0; i < n; ++i) {
                std::string x;
                input >> x;
                a.emplace_back(x);
            }
            if (operation == "mul") {
                for (uint32_t i = 0; i < n; ++i) {
                    std::string x;
                    input >> x;
                    b.emplace_back(x);
                }
            }
            if (!input) throw std::invalid_argument("Incomplete probe input");
            const auto from = mlwr::MakeRnsParams(n, source);
            const auto to = mlwr::MakeRnsParams(n, target);
            auto value = mlwr::FromCoefficients(from, a);
            if (operation == "round") value = mlwr::ScaleAndRound(value, to);
            else if (operation == "lift") value = mlwr::LiftCentered(value, to);
            else if (operation == "select") value = mlwr::SelectBasis(value, to);
            else if (operation == "mul") value *= mlwr::FromCoefficients(from, b);
            else if (operation == "rotate") value = mlwr::Automorphism(value, mlwr::RotationExponent(steps, n));
            else if (operation != "identity") throw std::invalid_argument("Unknown probe operation");
            const auto result = mlwr::Coefficients(value);
            std::cout << '[';
            for (std::size_t i = 0; i < result.size(); ++i) {
                if (i) std::cout << ',';
                std::cout << result[i];
            }
            std::cout << "]\n";
        } catch (const std::exception& error) {
            std::cerr << error.what() << '\n';
            std::cout << "{\"error\":true}\n";
        }
    }
}
