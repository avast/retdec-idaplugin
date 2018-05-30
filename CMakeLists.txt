cmake_minimum_required(VERSION 3.6)

project(retdec-idaplugin CXX)

# Set the default build type to 'Release'
if(NOT CMAKE_BUILD_TYPE)
	set(default_build_type "Release")
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# Check that obligatory parameters were defined.
if(NOT IDA_SDK_DIR)
	message(FATAL_ERROR "Path to IDA SDK was not specified. Use -DIDA_SDK_DIR=<path>.")
endif()
if(NOT EXISTS "${IDA_SDK_DIR}")
	message(FATAL_ERROR "Specified IDA SDK path does not exist.")
endif()

# Build parameters.
if(MSVC) # Windows
	# Disable warnings (there are too many of them, including warnings from
	# third-party libraries, which cannot be selectively disabled when using MSVC).
	string(REGEX REPLACE "/W[0-4]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W0")

	# Disable the min() and max() macros to prevent errors when using e.g.
	# std::numeric_limits<...>::max()
	# (http://stackoverflow.com/questions/1904635/warning-c4003-and-errors-c2589-and-c2059-on-x-stdnumeric-limitsintmax).
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /DNOMINMAX")
else() # Linux
	# Common options.
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra")

	# Ignore the following warnings (they are not fixable).
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
endif()

# Defines.
add_definitions(-D__IDP__ -D__PLUGIN__ -DNO_OBSOLETE_FUNCS)
add_definitions(-D__X64__)

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

add_subdirectory(deps)
add_subdirectory(scripts)
add_subdirectory(src)
