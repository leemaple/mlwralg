cmake_minimum_required(VERSION 3.20)
project(mlwralg VERSION 0.1.0 LANGUAGES CXX)
option(MLWR_P03_PATCH "Link the separately built pinned P03 OpenFHE transform port" OFF)

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

add_library(mlwr src/rns.cpp src/profile.cpp src/scheme.cpp src/options.cpp src/compact.cpp src/bootstrap.cpp src/gadget.cpp)
target_include_directories(mlwr PUBLIC include)
target_link_libraries(mlwr PUBLIC mlwr_openfhe)
target_compile_options(mlwr PRIVATE -Wall -Wextra -Wpedantic)
if(MLWR_P03_PATCH)
    target_compile_definitions(mlwr PRIVATE MLWR_P03_PATCH=1)
endif()
add_executable(mlwr_demo apps/mlwr_demo.cpp)
target_link_libraries(mlwr_demo PRIVATE mlwr)
add_executable(mlwr_experiment apps/mlwr_experiment.cpp apps/compact_experiment.cpp)
target_link_libraries(mlwr_experiment PRIVATE mlwr)
add_executable(mlwr_bootstrap apps/mlwr_bootstrap.cpp)
target_link_libraries(mlwr_bootstrap PRIVATE mlwr)
add_executable(standard_gadget_checks tests/standard_gadget_checks.cpp)
target_link_libraries(standard_gadget_checks PRIVATE mlwr)
add_executable(bootstrap_checks tests/bootstrap_checks.cpp)
target_link_libraries(bootstrap_checks PRIVATE mlwr)

enable_testing()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME bootstrap_bridge_contract COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_recorded_check.py
    ${CMAKE_BINARY_DIR}/evidence/bootstrap-contract.json $<TARGET_FILE:bootstrap_checks>)
set_tests_properties(bootstrap_bridge_contract PROPERTIES TIMEOUT 180)
add_test(NAME bootstrap_parameter_configuration COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_bootstrap_cli.py $<TARGET_FILE:mlwr_bootstrap>)
add_test(NAME sparse_clear_transform_oracle COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_sparse_transform_oracle.py)
add_test(NAME standard_gadget_contract COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_recorded_check.py
    ${CMAKE_BINARY_DIR}/evidence/standard-gadget.json $<TARGET_FILE:standard_gadget_checks>)
set_tests_properties(standard_gadget_contract PROPERTIES TIMEOUT 180)
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
add_executable(parameter_checks tests/parameter_checks.cpp)
target_link_libraries(parameter_checks PRIVATE mlwr)
add_test(NAME adjustable_parameters COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_recorded_check.py
    ${CMAKE_BINARY_DIR}/evidence/parameters.json $<TARGET_FILE:parameter_checks>)
add_test(NAME parameter_configuration COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_recorded_check.py
    ${CMAKE_BINARY_DIR}/evidence/parameter-cli.json ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_parameters.py $<TARGET_FILE:mlwr_demo>)
set_tests_properties(adjustable_parameters parameter_configuration PROPERTIES TIMEOUT 600)
add_executable(compact_checks tests/compact_checks.cpp)
target_link_libraries(compact_checks PRIVATE mlwr)
add_test(NAME compact_pair_contract COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_recorded_check.py
    ${CMAKE_BINARY_DIR}/evidence/compact-contract.json $<TARGET_FILE:compact_checks>)
set_tests_properties(compact_pair_contract PROPERTIES TIMEOUT 600)
add_test(NAME compact_parameter_configuration COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_recorded_check.py
    ${CMAKE_BINARY_DIR}/evidence/compact-cli.json ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_compact_cli.py $<TARGET_FILE:mlwr_experiment>)
