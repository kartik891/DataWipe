cmake_minimum_required(VERSION 3.20)
project(datawipe VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion -Werror)

# Everything except main() lives in one static library so tests link the same code the CLI runs.
# Platform layer: how disks are found, opened and sent commands.
if(WIN32)
  set(DW_PLATFORM_SOURCES
    src/platform/win_compat.cpp
    src/platform/win_device.cpp)
else()
  set(DW_PLATFORM_SOURCES
    src/device/sysfs.cpp
    src/device/loop_device.cpp
    src/device/passthrough_linux.cpp)
endif()

add_library(datawipe_core STATIC
  src/core/log.cpp
  src/core/json.cpp
  src/core/chacha20.cpp
  src/core/sha256.cpp
  src/core/cancel.cpp
  src/device/block_device.cpp
  src/device/image_device.cpp
  src/device/safety_guard.cpp
  src/device/device_factory.cpp
  src/device/simulated_identity.cpp
  src/device/ata_identity.cpp
  src/device/classifier.cpp
  src/device/ata_taskfile.cpp
  src/device/passthrough.cpp
  src/device/hw_identity.cpp
  src/device/win_storage.cpp
  src/engine/device_command.cpp
  src/engine/wipe_plan.cpp
  src/engine/method_selector.cpp
  src/engine/simulated_executor.cpp
  src/engine/plan_executor.cpp
  src/engine/pattern.cpp
  src/engine/overwrite_engine.cpp
  src/engine/run_journal.cpp
  src/engine/command_support.cpp
  src/engine/passthrough_executor.cpp
  src/verify/sector_sampler.cpp
  src/verify/readback_verifier.cpp
  src/verify/risk_model.cpp
  src/verify/arvs_sampler.cpp
  src/verify/sci.cpp
  src/verify/fingerprint.cpp
  src/cert/certificate.cpp
  src/cert/pdf.cpp
  src/tecc/ed25519.cpp
  src/tecc/session_chain.cpp
  ${DW_PLATFORM_SOURCES}
)
if(WIN32)
  # POSIX calls MinGW lacks (platform/win_compat.hpp); 64-bit file offsets; one self-contained .exe.
  target_compile_options(datawipe_core PUBLIC -include ${CMAKE_SOURCE_DIR}/src/platform/win_compat.hpp)
  target_compile_definitions(datawipe_core PUBLIC _FILE_OFFSET_BITS=64 _WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
  target_link_libraries(datawipe_core PUBLIC bcrypt ws2_32 crypt32)
  target_link_options(datawipe_core PUBLIC -static)
endif()
# The ChaCha20 lane loops only auto-vectorize at -O3; it is the engine's CPU hot path.
set_source_files_properties(src/core/chacha20.cpp PROPERTIES COMPILE_OPTIONS -O3)
# TECC signatures: Ed25519 from OpenSSL libcrypto (not hand-written crypto).
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
target_link_libraries(datawipe_core PUBLIC OpenSSL::Crypto)
target_include_directories(datawipe_core PUBLIC src)
target_compile_definitions(datawipe_core PRIVATE DW_VERSION="${PROJECT_VERSION}")

add_executable(datawipe src/cli/main.cpp src/cli/interactive.cpp)
target_link_libraries(datawipe PRIVATE datawipe_core)
target_compile_definitions(datawipe PRIVATE DW_VERSION="${PROJECT_VERSION}")

enable_testing()
foreach(t test_json test_ata_identity test_device test_engine test_hardware test_overwrite test_verify test_arvs test_tecc test_win_storage)
  add_executable(${t} tests/${t}.cpp)
  target_link_libraries(${t} PRIVATE datawipe_core)
  add_test(NAME ${t} COMMAND ${t})
  set_tests_properties(${t} PROPERTIES ENVIRONMENT "DW_PROFILES_DIR=${CMAKE_SOURCE_DIR}/profiles")
endforeach()

# End to end through the CLI on image files (unprivileged). The loop-device variant needs root:
#   sudo scripts/e2e.sh --loop
add_test(NAME e2e_image COMMAND ${CMAKE_SOURCE_DIR}/scripts/e2e.sh)
set_tests_properties(e2e_image PROPERTIES
  ENVIRONMENT "DATAWIPE=$<TARGET_FILE:datawipe>;PROFILES=${CMAKE_SOURCE_DIR}/profiles"
  SKIP_RETURN_CODE 77)

# Real kernel drivers against emulated SATA/NVMe drives in a throwaway VM (needs KVM,
# busybox-static, QEMU; downloads this machine's kernel package once). Skips otherwise.
add_test(NAME qemu_bench COMMAND ${CMAKE_SOURCE_DIR}/scripts/qemu_bench.py --datawipe $<TARGET_FILE:datawipe>)
set_tests_properties(qemu_bench PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 1500)

# The live image (UEFI + Secure Boot, BIOS; CD or USB): `make iso`. Its boot tests run the
# image in QEMU under real Secure Boot firmware and wipe a disk through the live menu.
add_custom_target(iso
  COMMAND ${CMAKE_SOURCE_DIR}/scripts/build_iso.py --datawipe $<TARGET_FILE:datawipe> --out ${CMAKE_BINARY_DIR}/datawipe-live.iso
  DEPENDS datawipe USES_TERMINAL)
add_test(NAME iso_boot COMMAND sh -c "${CMAKE_SOURCE_DIR}/scripts/build_iso.py --datawipe $<TARGET_FILE:datawipe> --out ${CMAKE_BINARY_DIR}/datawipe-live.iso >/dev/null && ${CMAKE_SOURCE_DIR}/scripts/iso_test.py --iso ${CMAKE_BINARY_DIR}/datawipe-live.iso --datawipe $<TARGET_FILE:datawipe>")
set_tests_properties(iso_boot PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 1800)

# ---- Install and packages: `cpack` in the build directory, or scripts/package.sh for a release.
include(GNUInstallDirs)
install(TARGETS datawipe RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY profiles/ DESTINATION ${CMAKE_INSTALL_DATADIR}/datawipe/profiles FILES_MATCHING PATTERN "*.json")
install(PROGRAMS scripts/hardware_test.sh DESTINATION ${CMAKE_INSTALL_DATADIR}/datawipe)
install(FILES README.md LICENSE packaging/copyright DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/datawipe)
add_custom_command(OUTPUT datawipe.1.gz
  COMMAND gzip -9nc ${CMAKE_SOURCE_DIR}/doc/datawipe.1 > datawipe.1.gz
  DEPENDS doc/datawipe.1 VERBATIM)
add_custom_target(manpage ALL DEPENDS datawipe.1.gz)
install(FILES ${CMAKE_BINARY_DIR}/datawipe.1.gz DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

set(CPACK_PACKAGE_NAME datawipe)
set(CPACK_PACKAGE_VENDOR "DataWipe")
set(CPACK_PACKAGE_CONTACT "DataWipe <datawipe21@gmail.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Disk sanitization with read-back verification and signed certificates")
set(CPACK_PACKAGE_DESCRIPTION "Erases HDDs, SSDs and eMMC following NIST SP 800-88 (Clear and Purge),
verifies the result by risk-weighted read-back sampling (ARVS) scored with the
Sanitization Confidence Index (SCI), and issues a hash-chained certificate
signed with the issuing organisation's Ed25519 key (TECC). Includes a guided
terminal mode. Wiping is destructive: physical disks need an explicit flag and
the serial number retyped.")
set(CPACK_GENERATOR "DEB;TGZ")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_STRIP_FILES ON)
set(CPACK_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION admin)
set(CPACK_DEBIAN_PACKAGE_PRIORITY optional)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_ARCHIVE_FILE_NAME "datawipe-${PROJECT_VERSION}-linux-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGE_FILE_NAME "datawipe-${PROJECT_VERSION}-linux-${CMAKE_SYSTEM_PROCESSOR}")
include(CPack)
