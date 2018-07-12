##
## CMake build script for the IDA Pro plugin.
##

# Inspired by https://github.com/google/idaidle/blob/master/FindIdaSdk.cmake
# Target name *MUST* be the same as plugin source directory.
set(TARGET_NAME "idaplugin")
set(FINAL_PLUGIN_NAME "retdec")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
         "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR
		 "${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang")
	set(IDA_LIB_PATH_COMPILER "gcc")
	set(IDA_LIB_PATH_NAME "libida")
	set(IDA_PLUGIN_USER_INSTALL_PATH "~/.idapro/plugins")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	set(IDA_LIB_PATH_COMPILER "vc")
	set(IDA_LIB_PATH_NAME "ida")
	set(IDA_PLUGIN_USER_INSTALL_PATH "%AppData%\Hex-Rays\IDA Pro\plugins")
endif()

if(EA64 GREATER_EQUAL 1)
	set(FINAL_IDA_PLUGIN_NAME "${FINAL_PLUGIN_NAME}64")
	set(IDA_LIB_PATH_TARGET "64")
	set(IDA_LIB_ARCH_NAME "64")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")
else()
	set(FINAL_IDA_PLUGIN_NAME "${FINAL_PLUGIN_NAME}")
	set(IDA_LIB_PATH_TARGET "32")
	set(IDA_LIB_ARCH_NAME "")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
endif()

# Windows.
if(MSVC OR MSYS)
	set(IDA_SDK_PLATFORM __NT__)

	set(IDA_LIB_PATH_PLATFORM "win")
	set(IDA_LIB_PATH_EXTENSION "lib")
	set(PLUGIN_EXTENSION "dll")
# macOS
elseif(APPLE)
	set(IDA_SDK_PLATFORM __MAC__)

	set(IDA_LIB_PATH_PLATFORM "mac")
	set(IDA_LIB_PATH_EXTENSION "dylib")
	set(PLUGIN_EXTENSION "dylib")
# Linux.
elseif(UNIX)
	set(IDA_SDK_PLATFORM __LINUX__)

	set(IDA_LIB_PATH_PLATFORM "linux")
	set(IDA_LIB_PATH_EXTENSION "so")
	set(PLUGIN_EXTENSION "so")
else()
  message(FATAL_ERROR "Unsupported system type: ${CMAKE_SYSTEM_NAME}")
endif()

set(IDASDK_LIBRARIES "${IDA_SDK_DIR}/lib/x64_${IDA_LIB_PATH_PLATFORM}_${IDA_LIB_PATH_COMPILER}_${IDA_LIB_PATH_TARGET}/${IDA_LIB_PATH_NAME}${IDA_LIB_ARCH_NAME}.${IDA_LIB_PATH_EXTENSION}")

# Make our includes work.
include_directories("..")

# Make includes from IDA SDK work.
include_directories(SYSTEM
	"${IDA_SDK_DIR}/include"
)

# Src Files.
set(IDAPLUGIN_SOURCES
	code_viewer.cpp
	config_generator.cpp
	decompiler.cpp
	defs.cpp
	idaplugin.cpp
	plugin_config.cpp
)

add_library(${TARGET_NAME} SHARED ${IDAPLUGIN_SOURCES})

# Support for 64-bit addresses.
if(EA64 GREATER_EQUAL 1)
	target_compile_definitions(${TARGET_NAME} PUBLIC __EA64__)
endif()

# Build 64-bit by default.
target_compile_definitions(${TARGET_NAME} PUBLIC __X64__)

# Add the necessary __IDP__ define and allow to use "dangerous" and standard
# file functions.
target_compile_definitions(${TARGET_NAME} PUBLIC
							${IDA_SDK_PLATFORM}
							__IDP__
							__PLUGIN__
							NO_OBSOLETE_FUNCS
							USE_DANGEROUS_FUNCTIONS
							USE_STANDARD_FILE_FUNCTIONS
)

set_target_properties(${TARGET_NAME} PROPERTIES PREFIX "" SUFFIX "")
if(UNIX)
	set(CMAKE_CXX_FLAGS -m64)
	# Always use the linker script needed for IDA.
	target_compile_options(${TARGET_NAME} PUBLIC ${CMAKE_CXX_FLAGS})
	if(APPLE)
		target_link_libraries(${TARGET_NAME} ${CMAKE_CXX_FLAGS}
								-Wl,-flat_namespace
								-Wl,-undefined,warning
								-Wl,-exported_symbol,_PLUGIN)
	else()
		target_link_libraries(${TARGET_NAME} ${CMAKE_CXX_FLAGS})
	endif()
elseif(WIN32)
	# shlwapi.dll for PathRemoveFileSpec() used in utilsl/filesystem_path.h
	target_link_libraries(${TARGET_NAME} shlwapi)
elseif(MSYS)
	target_link_libraries(${TARGET_NAME} ws2_32)
endif()

# For qrefcnt_obj_t in ida.hpp
target_compile_options(${TARGET_NAME} PUBLIC -Wno-non-virtual-dtor)

target_link_libraries(${TARGET_NAME}
	retdec
	jsoncpp
	${IDASDK_LIBRARIES}
)

set_property(TARGET ${TARGET_NAME} PROPERTY CXX_STANDARD 14)

# Set a proper name of the library that represents the plugin (e.g. retdec.dylib
# on macOS, retdec.so on Linux and retdec.dll on Windows).
set_target_properties(${TARGET_NAME} PROPERTIES PREFIX "")
set_target_properties(${TARGET_NAME} PROPERTIES OUTPUT_NAME "${FINAL_IDA_PLUGIN_NAME}.${PLUGIN_EXTENSION}")

if(IDA_PATH)
	install(TARGETS ${TARGET_NAME}
		LIBRARY DESTINATION "${IDA_PATH}/plugins/"
		RUNTIME DESTINATION "${IDA_PATH}/plugins/"
	)
else()
	install(TARGETS ${TARGET_NAME}
		LIBRARY DESTINATION "${IDA_PLUGIN_USER_INSTALL_PATH}/"
		RUNTIME DESTINATION "${IDA_PLUGIN_USER_INSTALL_PATH}/"
	)
endif()
