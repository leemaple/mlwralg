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
target_link_libraries(openfhe_reference PRIVATE mlwr_openfhe)

enable_testing()
add_test(NAME openfhe_reference COMMAND openfhe_reference)
