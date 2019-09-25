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
#	code_viewer.cpp
#	config_generator.cpp
#	decompiler.cpp
#	defs.cpp
#	idaplugin.cpp
#	plugin_config.cpp

#	hexplace.cpp
#	hexview.cpp

	test.cpp
)

# RetDec idaplugin libs.
add_library(idaplugin32 SHARED ${IDAPLUGIN_SOURCES})
add_library(idaplugin64 SHARED ${IDAPLUGIN_SOURCES})

target_compile_definitions(idaplugin64 PUBLIC __EA64__)

target_link_libraries(idaplugin32 retdec jsoncpp ${idasdk_ea32})
target_link_libraries(idaplugin64 retdec jsoncpp ${idasdk_ea64})

if(WIN32)
	# shlwapi.dll for PathRemoveFileSpec() used in utilsl/filesystem_path.h
	target_link_libraries(idaplugin32 shlwapi)
	target_link_libraries(idaplugin64 shlwapi)
endif()
if(MSYS)
	target_link_libraries(idaplugin32 ws2_32)
	target_link_libraries(idaplugin64 ws2_32)
endif()

set_target_properties(idaplugin32 PROPERTIES PREFIX "")
set_target_properties(idaplugin64 PROPERTIES PREFIX "")
set_target_properties(idaplugin32 PROPERTIES OUTPUT_NAME "retdec")
set_target_properties(idaplugin64 PROPERTIES OUTPUT_NAME "retdec64")

# Installation.
if(IDA_PATH)
	install(TARGETS idaplugin32 idaplugin64
		LIBRARY DESTINATION "${IDA_PATH}/plugins/"
		RUNTIME DESTINATION "${IDA_PATH}/plugins/"
	)
endif()
