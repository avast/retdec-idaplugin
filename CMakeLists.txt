cmake_minimum_required(VERSION 3.11)

project(retdec-idaplugin CXX C)
set(RELEASE_VERSION "1.0-ida80")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(RETDEC_IDAPLUGIN_DOC "Build the documentation." OFF)

# Set the default build type to 'Release'
if(NOT CMAKE_BUILD_TYPE)
	set(default_build_type "Release")
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
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

	# Force static runtime
	string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
	string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})
	string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_RELWITHDEBINFO ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})
	string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_RELWITHDEBINFO ${CMAKE_C_FLAGS_RELWITHDEBINFO})
	string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_MINSIZEREL ${CMAKE_CXX_FLAGS_MINSIZEREL})
	string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_MINSIZEREL ${CMAKE_C_FLAGS_MINSIZEREL})
	string(REPLACE "/MDd" "/MT" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
	string(REPLACE "/MDd" "/MT" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MT")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /MT")
	set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} /MT")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MT")
	set(RETDEC_MSVC_STATIC_RUNTIME ON)
elseif(UNIX) # Linux or macOS
	# Common options.
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra")

	# Ignore the following warnings (they are not fixable).
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-non-virtual-dtor")

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
else()
	message(FATAL_ERROR "Unsupported system type: ${CMAKE_SYSTEM_NAME}")
endif()

# Global defines.
add_definitions(-D__IDP__ -D__PLUGIN__ -DNO_OBSOLETE_FUNCS)
add_definitions(-D__X64__)
add_definitions(-DRELEASE_VERSION="${RELEASE_VERSION}")
if(WIN32)
	add_definitions(-D__NT__)
elseif(APPLE)
	add_definitions(-D__MAC__)
elseif(UNIX) # APPLE is also UNIX, so it MUST be before this elseif().
	add_definitions(-D__LINUX__)
else()
	message(FATAL_ERROR "Unsupported system type: ${CMAKE_SYSTEM_NAME}")
endif()

# Subdirectories.
add_subdirectory(deps)
if(RETDEC_IDAPLUGIN_DOC)
	add_subdirectory(doc)
endif()
add_subdirectory(scripts)
add_subdirectory(src)

# Create release.
if(RETDEC_IDAPLUGIN_DOC)
	set(RELEASE_DIR_NAME "retdec-idaplugin")
	set(RELEASE_DIR "${CMAKE_CURRENT_BINARY_DIR}/${RELEASE_DIR_NAME}")
	set(RELEASE_RESOURCES_DIR "${RELEASE_DIR}/retdec")
	if(MSVC) # Windows
		set(RELEASE_OS_NAME "windows")
	elseif(APPLE) # macOS
		set(RELEASE_OS_NAME "macOS")
	else() # Linux
		set(RELEASE_OS_NAME "linux")
	endif()
	add_custom_target(release
		DEPENDS user-guide idaplugin32 idaplugin64
		# Create directory structure.
		COMMAND ${CMAKE_COMMAND} -E make_directory "${RELEASE_DIR}"
		COMMAND ${CMAKE_COMMAND} -E make_directory "${RELEASE_RESOURCES_DIR}"
		# Copy plugins.
		COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:idaplugin32>" "${RELEASE_DIR}"
		COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:idaplugin64>" "${RELEASE_DIR}"
		# Copy resources.
		COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/README.md" "${RELEASE_RESOURCES_DIR}"
		COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/CHANGELOG.md" "${RELEASE_RESOURCES_DIR}"
		COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/LICENSE" "${RELEASE_RESOURCES_DIR}"
		COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/LICENSE-THIRD-PARTY" "${RELEASE_RESOURCES_DIR}"
		COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/doc/user_guide/user_guide.pdf" "${RELEASE_RESOURCES_DIR}"
		COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/src/idaplugin/decompiler-config.json" "${RELEASE_RESOURCES_DIR}"
		COMMAND ${CMAKE_COMMAND} -E copy_directory "${retdec_SOURCE_DIR}/support/ordinals" "${RELEASE_RESOURCES_DIR}/ordinals/"
		COMMAND ${CMAKE_COMMAND} -E copy_directory "${retdec_SOURCE_DIR}/support/yara_patterns" "${RELEASE_RESOURCES_DIR}/yara_patterns/"
		COMMAND ${CMAKE_COMMAND} -E copy_directory "${retdec_SOURCE_DIR}/support/types" "${RELEASE_RESOURCES_DIR}/types/"
		# Create the archive.
		COMMAND ${CMAKE_COMMAND} -E tar "cvf" "${CMAKE_CURRENT_BINARY_DIR}/${RELEASE_DIR_NAME}-v${RELEASE_VERSION}-${RELEASE_OS_NAME}.zip" --format=zip "${RELEASE_DIR}"
	)
endif()
