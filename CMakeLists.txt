
cmake_minimum_required(VERSION 3.6)

project(retdec-idaplugin CXX)

# Set the default build type to 'Release'
if(NOT CMAKE_BUILD_TYPE)	
	set(default_build_type "Release")
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# Check that obligatory parameters were defined.
if(NOT IDAPLUGIN_LIBS_DIR)
	message(FATAL_ERROR "Path to idaplugin libraries was not specified. Use -DIDAPLUGIN_LIBS_DIR=<path>.")
endif()
if(NOT EXISTS "${IDAPLUGIN_LIBS_DIR}")
	message(FATAL_ERROR "Specified idaplugin libraries path does not exist.")
endif()

if(NOT IDA_SDK_DIR)
	message(FATAL_ERROR "Path to IDA SDK was not specified. Use -DIDA_SDK_DIR=<path>.")
endif()
if(NOT EXISTS "${IDA_SDK_DIR}")
	message(FATAL_ERROR "Specified IDA SDK path does not exist.")
endif()

add_subdirectory(scripts)
add_subdirectory(src)
