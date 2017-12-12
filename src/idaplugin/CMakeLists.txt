##
## CMake build script for the IDA Pro plugin.
##

##
## retdec-cpp
##

# The plugin uses several third-party libraries, so make their includes work.
include_directories(SYSTEM
	"${IDAPLUGIN_LIBS_DIR}/boost/include"
	"${IDAPLUGIN_LIBS_DIR}/cpp-netlib/include"
	"${IDAPLUGIN_LIBS_DIR}/jsoncpp/include"
	"${IDAPLUGIN_LIBS_DIR}/openssl/include"
	"${IDAPLUGIN_LIBS_DIR}/retdec-cpp/include"
)

# The order of the libraries below is important (at least on Windows).
# Otherwise, there are "undefined reference" problems.
if(MSVC)
	set(RETDEC_LIBRARIES
		"${IDAPLUGIN_LIBS_DIR}/retdec-cpp/lib/retdec.lib"
		"${IDAPLUGIN_LIBS_DIR}/cpp-netlib/lib/cppnetlib-client-connections.lib"
		"${IDAPLUGIN_LIBS_DIR}/cpp-netlib/lib/cppnetlib-uri.lib"
		"${IDAPLUGIN_LIBS_DIR}/openssl/lib/libeay32MT.lib"
		"${IDAPLUGIN_LIBS_DIR}/openssl/lib/ssleay32MT.lib"
		"${IDAPLUGIN_LIBS_DIR}/jsoncpp/lib/jsoncpp.lib"
		# Do not link with boost libraries manually because MSVC links them
		# automatically (see the comment below concerning the use of
		# link_directories()). Linking them twice results into "multiple
		# definition" errors.
	)
	# Without adding the boost/lib directory into the path where MSVC searches
	# for libraries, MSVC fails with the following error:
	#
	#     LINK : fatal error LNK1104: cannot open file 'libboost_thread-vc140-mt-1_59.lib'
	#
	# I have no idea why (I tried to find a reason, but I was unable to find
	# it). There is a benefit, though: we do not have to link the boost
	# libraries manually.
	link_directories("${IDAPLUGIN_LIBS_DIR}/boost/lib")
else() # GCC
	set(RETDEC_LIBRARIES
		"${IDAPLUGIN_LIBS_DIR}/retdec-cpp/lib/libretdec.a"
		"${IDAPLUGIN_LIBS_DIR}/cpp-netlib/lib/libcppnetlib-client-connections.a"
		"${IDAPLUGIN_LIBS_DIR}/cpp-netlib/lib/libcppnetlib-uri.a"
		"${IDAPLUGIN_LIBS_DIR}/boost/lib/libboost_filesystem.a"
		"${IDAPLUGIN_LIBS_DIR}/boost/lib/libboost_system.a"
		"${IDAPLUGIN_LIBS_DIR}/boost/lib/libboost_thread.a"
		"${IDAPLUGIN_LIBS_DIR}/openssl/lib/libssl.a"
		"${IDAPLUGIN_LIBS_DIR}/openssl/lib/libcrypto.a"
		"${IDAPLUGIN_LIBS_DIR}/jsoncpp/lib/libjsoncpp.a"
	)
endif()

##
## idaplugin
##

# Target name *MUST* be the same as plugin source directory.
set(TARGET_NAME "idaplugin")
set(FINAL_PLUGIN_NAME "retdec")

# Build parameters.
if(MSVC)
	# Disable warnings (there are too many of them, including warnings from
	# third-party libraries, which cannot be selectively disabled when using MSVC).
	string(REGEX REPLACE "/W[0-4]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W0")

	# Disable the min() and max() macros to prevent errors when using e.g.
	# std::numeric_limits<...>::max()
	# (http://stackoverflow.com/questions/1904635/warning-c4003-and-errors-c2589-and-c2059-on-x-stdnumeric-limitsintmax).
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /DNOMINMAX")
else() # Linux/MSYS
	# Common options.
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra")

	# Ignore the following warnings (they are not fixable).
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")

	# 32-bit plugin.
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")

	# On Windows, link statically to minimize external dependencies.
	if(MSYS)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
	endif()
endif()

# Defines.
add_definitions(-DBOOST_NETWORK_ENABLE_HTTPS)
add_definitions(-D__IDP__ -D__PLUGIN__ -DNO_OBSOLETE_FUNCS)

if(NOT MSVC)
	# Use the old C++ ABI in stdlibc++. This allows us to build the plugin with
	# both GCC >= 5.1 and Clang while keeping the same build of IDA SDK and IDA
	# plugin libraries ($ROOT_DIR/{idasdk,idaplugin-libs}). Otherwise, we would
	# need to rebuild them with the new ABI, which is impossible since IDA SDK
	# distributes only binary packages.
	#
	# See the following link for more details:
	#
	#     https://gcc.gnu.org/onlinedocs/libstdc++/manual/using_dual_abi.html
	#
	add_definitions(-D_GLIBCXX_USE_CXX11_ABI=0)
endif()

# Windows.
if(WIN32)
	set(FINAL_PLUGIN_NAME "${FINAL_PLUGIN_NAME}.plw")

	# _WIN32_WINNT is defined for Boost (otherwise, it complains during
	# compilation). It is the minimum required system for running the plugin.
	# 0x0501 is WindowsXP.
	add_definitions(-D__NT__ -DWIN32 -D_WIN32_WINNT=0x0501)

	if(MSVC)
		set(IDASDK_LIBRARIES "${IDA_SDK_DIR}/lib/x86_win_vc_32/ida.lib")
	else() # GCC
		set(IDASDK_LIBRARIES "${IDA_SDK_DIR}/lib/x86_win_gcc_32/ida.a")
	endif()
# Linux.
else()
	set(FINAL_PLUGIN_NAME "${FINAL_PLUGIN_NAME}.plx")

	add_definitions(-D__LINUX__)

	# From idasdk/readme.txt:
	# There are no ida.a libraries for Linux, since you can link directly
	# to the shared library of the IDA kernel (libida.so or libida.dylib).
	# This shared library comes with IDA itself (not with the SDK).
	set(IDASDK_LIBRARIES "")
endif()

# Make our includes work.
include_directories("..")

# Make includes from IDA SDK work.
include_directories(SYSTEM
	"${IDA_SDK_DIR}/.." # So we can include idasdk's headers as "<idasdk/include/*.hpp>".
	"${IDA_SDK_DIR}/include"
	"../../deps/tl-cpputils/include"
	"../../deps/retdec-config/include"
)

# Build.
set(TL_CPPUTILS_SOURCES
	../../deps/tl-cpputils/src/tl-cpputils/address.cpp
	../../deps/tl-cpputils/src/tl-cpputils/alignment.cpp
	../../deps/tl-cpputils/src/tl-cpputils/byte_value_storage.cpp
	../../deps/tl-cpputils/src/tl-cpputils/conversion.cpp
	../../deps/tl-cpputils/src/tl-cpputils/file_io.cpp
	../../deps/tl-cpputils/src/tl-cpputils/filesystem_path.cpp
	../../deps/tl-cpputils/src/tl-cpputils/math.cpp
	../../deps/tl-cpputils/src/tl-cpputils/string.cpp
	../../deps/tl-cpputils/src/tl-cpputils/system.cpp
	../../deps/tl-cpputils/src/tl-cpputils/time.cpp
)
set(RETDEC_CONFIG_SOURCES
	../../deps/retdec-config/src/retdec-config/architecture.cpp
	../../deps/retdec-config/src/retdec-config/base.cpp
	../../deps/retdec-config/src/retdec-config/calling_convention.cpp
	../../deps/retdec-config/src/retdec-config/classes.cpp
	../../deps/retdec-config/src/retdec-config/config.cpp
	../../deps/retdec-config/src/retdec-config/file_format.cpp
	../../deps/retdec-config/src/retdec-config/file_type.cpp
	../../deps/retdec-config/src/retdec-config/functions.cpp
	../../deps/retdec-config/src/retdec-config/language.cpp
	../../deps/retdec-config/src/retdec-config/objects.cpp
	../../deps/retdec-config/src/retdec-config/parameters.cpp
	../../deps/retdec-config/src/retdec-config/patterns.cpp
	../../deps/retdec-config/src/retdec-config/segments.cpp
	../../deps/retdec-config/src/retdec-config/storage.cpp
	../../deps/retdec-config/src/retdec-config/tool_info.cpp
	../../deps/retdec-config/src/retdec-config/types.cpp
	../../deps/retdec-config/src/retdec-config/vtables.cpp
)
set(IDAPLUGIN_SOURCES
	code_viewer.cpp
	config_generator.cpp
	decompiler.cpp
	defs.cpp
	idaplugin.cpp
	plugin_config.cpp
)

add_library(${TARGET_NAME} SHARED
	${IDAPLUGIN_SOURCES}
	${TL_CPPUTILS_SOURCES}
	${RETDEC_CONFIG_SOURCES}
)
target_link_libraries(${TARGET_NAME}
	${RETDEC_LIBRARIES}
	${IDASDK_LIBRARIES}
)
if(WIN32)
	# shlwapi.dll for PathRemoveFileSpec() used in utilsl/filesystem_path.h
	target_link_libraries(${TARGET_NAME} shlwapi)
endif()
if(MSYS)
	target_link_libraries(${TARGET_NAME} ws2_32)
endif()

# Set a proper name of the library that represents the plugin (e.g. retdec.plx
# on Linux and retdec.plw on Windows).
set_target_properties(${TARGET_NAME} PROPERTIES PREFIX "")
set_target_properties(${TARGET_NAME} PROPERTIES SUFFIX "")
set_target_properties(${TARGET_NAME} PROPERTIES OUTPUT_NAME "${FINAL_PLUGIN_NAME}")

if(IDA_PATH)
	install(TARGETS ${TARGET_NAME} 
		LIBRARY DESTINATION "${IDA_PATH}/plugins/"
		RUNTIME DESTINATION "${IDA_PATH}/plugins/"
	)
endif()
