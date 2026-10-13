cmake_minimum_required(VERSION 3.20)
project(mlwralg VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenFHE 1.6.1 EXACT CONFIG REQUIRED)
find_package(Threads REQUIRED)
if(NOT OpenFHE_NATIVE_SIZE STREQUAL "64")
    message(FATAL_ERROR "This implementation requires OpenFHE NATIVE_SIZE=64")
endif()

add_library(mlwr_openfhe INTERFACE)
target_include_directories(mlwr_openfhe SYSTEM INTERFACE
    "${OpenFHE_INCLUDE}"
    "${OpenFHE_INCLUDE}/core"
    "${OpenFHE_INCLUDE}/pke"
    "${OpenFHE_INCLUDE}/binfhe"
    "${OpenFHE_INCLUDE}/third-party/include")
target_compile_definitions(mlwr_openfhe INTERFACE MATHBACKEND=${OpenFHE_BACKEND})
target_link_libraries(mlwr_openfhe INTERFACE ${OpenFHE_LIBRARIES} Threads::Threads)
if(OpenFHE_OPENMP)
    find_package(OpenMP REQUIRED)
    target_link_libraries(mlwr_openfhe INTERFACE OpenMP::OpenMP_CXX)
endif()

add_executable(openfhe_reference apps/openfhe_reference.cpp)
target_link_libraries(openfhe_reference PRIVATE mlwr)

add_library(mlwr src/rns.cpp src/profile.cpp src/scheme.cpp)
target_include_directories(mlwr PUBLIC include)
target_link_libraries(mlwr PUBLIC mlwr_openfhe)
target_compile_options(mlwr PRIVATE -Wall -Wextra -Wpedantic)
add_executable(mlwr_demo apps/mlwr_demo.cpp)
target_link_libraries(mlwr_demo PRIVATE mlwr)
add_executable(mlwr_experiment apps/mlwr_experiment.cpp)
target_link_libraries(mlwr_experiment PRIVATE mlwr)

enable_testing()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME openfhe_reference COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_recorded_check.py
    ${CMAKE_BINARY_DIR}/evidence/openfhe-reference.json $<TARGET_FILE:openfhe_reference>)
add_executable(rns_probe tests/rns_probe.cpp)
target_link_libraries(rns_probe PRIVATE mlwr)
add_test(NAME rns_integer_oracle
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_rns_oracle.py $<TARGET_FILE:rns_probe>)
add_test(NAME source_counterexamples
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_recorded_check.py
    ${CMAKE_BINARY_DIR}/evidence/source-counterexamples.json
    ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_source_counterexamples.py)
add_executable(mlwr_checks tests/mlwr_checks.cpp)
target_link_libraries(mlwr_checks PRIVATE mlwr)
add_test(NAME mlwr_correctness COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_recorded_check.py
    ${CMAKE_BINARY_DIR}/evidence/mlwr.json $<TARGET_FILE:mlwr_checks>)
set_tests_properties(mlwr_correctness PROPERTIES TIMEOUT 600)
