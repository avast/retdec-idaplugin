##
## CMake build script for the IDA Pro plugin.
##

# IDA SDK libs.
if(WIN32)
	set(idasdk_ea32 "${IDA_SDK_DIR}/lib/x64_win_vc_32/ida.lib")
	set(idasdk_ea64 "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
elseif(APPLE)
	set(idasdk_ea32 "${IDA_SDK_DIR}/lib/x64_mac_gcc_32/libida.dylib")
	set(idasdk_ea64 "${IDA_SDK_DIR}/lib/x64_mac_gcc_64/libida64.dylib")
elseif(UNIX) # APPLE is also UNIX, so it MUST be before this elseif().
	set(idasdk_ea32 "${IDA_SDK_DIR}/lib/x64_linux_gcc_32/libida.so")
	set(idasdk_ea64 "${IDA_SDK_DIR}/lib/x64_linux_gcc_64/libida64.so")
else()
	message(FATAL_ERROR "Unsupported system type: ${CMAKE_SYSTEM_NAME}")
endif()

# Includes.
include_directories("..") # Make our includes work.
include_directories(SYSTEM
	"${IDA_SDK_DIR}/include" # Make IDA SDK includes work.
)

# RetDec idaplugin sources.
set(IDAPLUGIN_SOURCES
	config.cpp
	function.cpp
	place.cpp
	token.cpp
	retdec.cpp
	ui.cpp
	utils.cpp
	yx.cpp
)

# RetDec idaplugin libs.
add_library(idaplugin32 SHARED ${IDAPLUGIN_SOURCES})
add_library(idaplugin64 SHARED ${IDAPLUGIN_SOURCES})

target_compile_definitions(idaplugin64 PUBLIC __EA64__)

target_link_libraries(idaplugin32 ${idasdk_ea32} retdec::retdec retdec::config retdec::utils retdec::deps::rapidjson)
target_link_libraries(idaplugin64 ${idasdk_ea64} retdec::retdec retdec::config retdec::utils retdec::deps::rapidjson)

if(MSYS)
	target_link_libraries(idaplugin32 ws2_32)
	target_link_libraries(idaplugin64 ws2_32)
endif()

# Due to the implementation of the plugin system in LLVM, we have to link our
# libraries into retdec as a whole.
if(MSVC)
	# -WHOLEARCHIVE needs path to the target, but when we use the target like
	# that, its properties (associated includes, etc.) are not propagated.
	# Therefore, we state 'bin2llvmir|llvmir2hll' twice in target_link_libraries(),
	# first as a target to get its properties, second as path to library to
	# link it as a whole.
	target_link_libraries(idaplugin32
		retdec::bin2llvmir -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::bin2llvmir>
		retdec::llvmir2hll -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::llvmir2hll>
	)
	target_link_libraries(idaplugin64
		retdec::bin2llvmir -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::bin2llvmir>
		retdec::llvmir2hll -WHOLEARCHIVE:$<TARGET_FILE_NAME:retdec::llvmir2hll>
	)
	set_property(TARGET idaplugin32
		APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE"
	)
	set_property(TARGET idaplugin64
		APPEND_STRING PROPERTY LINK_FLAGS " /FORCE:MULTIPLE"
	)
	# Increase the stack size of the created binaries on MS Windows because the
	# default value is too small. The default Linux value is 8388608 (8 MB).
	set_property(TARGET idaplugin32
		APPEND_STRING PROPERTY LINK_FLAGS " /STACK:16777216"
	)
	set_property(TARGET idaplugin64
		APPEND_STRING PROPERTY LINK_FLAGS " /STACK:16777216"
	)
	# Allow the 32b version of bin2llvmir on Windows handle addresses larger
	# than 2 GB (up to 4 GB).
	if(CMAKE_SIZEOF_VOID_P MATCHES "4")
		set_property(TARGET idaplugin32
			APPEND_STRING PROPERTY LINK_FLAGS " /LARGEADDRESSAWARE"
		)
	endif()
	if(CMAKE_SIZEOF_VOID_P MATCHES "4")
		set_property(TARGET idaplugin64
			APPEND_STRING PROPERTY LINK_FLAGS " /LARGEADDRESSAWARE"
		)
	endif()
elseif(APPLE)
	target_link_libraries(idaplugin32
		-Wl,-force_load retdec::bin2llvmir
		-Wl,-force_load retdec::llvmir2hll
	)
	target_link_libraries(idaplugin64
		-Wl,-force_load retdec::bin2llvmir
		-Wl,-force_load retdec::llvmir2hll
	)
else() # Linux
	target_link_libraries(idaplugin32
		-Wl,--whole-archive retdec::bin2llvmir -Wl,--no-whole-archive
		-Wl,--whole-archive retdec::llvmir2hll -Wl,--no-whole-archive
	)
	target_link_libraries(idaplugin64
		-Wl,--whole-archive retdec::bin2llvmir -Wl,--no-whole-archive
		-Wl,--whole-archive retdec::llvmir2hll -Wl,--no-whole-archive
	)
endif()

set_target_properties(idaplugin32 PROPERTIES PREFIX "")
set_target_properties(idaplugin64 PROPERTIES PREFIX "")
set_target_properties(idaplugin32 PROPERTIES OUTPUT_NAME "retdec")
set_target_properties(idaplugin64 PROPERTIES OUTPUT_NAME "retdec64")

# Installation.
if(IDA_DIR)
	install(TARGETS idaplugin32 idaplugin64
		LIBRARY DESTINATION "${IDA_DIR}/plugins/"
		RUNTIME DESTINATION "${IDA_DIR}/plugins/"
	)
	install(
		FILES "decompiler-config.json"
		DESTINATION "${IDA_DIR}/plugins/retdec/"
	)
endif()
