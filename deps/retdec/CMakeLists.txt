include(ExternalProject)

ExternalProject_Add(retdec-project
	URL https://github.com/avast/retdec/archive/10c0ddcf5e0fdb8ee4c5256787a0fa74bd069883.zip
	URL_HASH SHA256=2e2112ac8d5a31721c2cafe3d7657b13b5efaed9b22486e20fd2ac8de79a7311
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the build step.
	BUILD_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

# Set include directories.
ExternalProject_Get_Property(retdec-project source_dir)
ExternalProject_Get_Property(retdec-project binary_dir)

set(RETDEC_UTILS_SOURCES
	${source_dir}/src/utils/address.cpp
	${source_dir}/src/utils/alignment.cpp
	${source_dir}/src/utils/byte_value_storage.cpp
	${source_dir}/src/utils/conversion.cpp
	${source_dir}/src/utils/file_io.cpp
	${source_dir}/src/utils/filesystem_path.cpp
	${source_dir}/src/utils/math.cpp
	${source_dir}/src/utils/string.cpp
	${source_dir}/src/utils/system.cpp
	${source_dir}/src/utils/time.cpp
)
set(RETDEC_CONFIG_SOURCES
	${source_dir}/src/config/architecture.cpp
	${source_dir}/src/config/base.cpp
	${source_dir}/src/config/calling_convention.cpp
	${source_dir}/src/config/classes.cpp
	${source_dir}/src/config/config.cpp
	${source_dir}/src/config/file_format.cpp
	${source_dir}/src/config/file_type.cpp
	${source_dir}/src/config/functions.cpp
	${source_dir}/src/config/language.cpp
	${source_dir}/src/config/objects.cpp
	${source_dir}/src/config/parameters.cpp
	${source_dir}/src/config/patterns.cpp
	${source_dir}/src/config/segments.cpp
	${source_dir}/src/config/storage.cpp
	${source_dir}/src/config/tool_info.cpp
	${source_dir}/src/config/types.cpp
	${source_dir}/src/config/vtables.cpp
)

add_custom_command(OUTPUT ${RETDEC_UTILS_SOURCES} ${RETDEC_CONFIG_SOURCES} DEPENDS retdec-project)

# Add libraries.
add_library(retdec ${RETDEC_UTILS_SOURCES} ${RETDEC_CONFIG_SOURCES})
add_dependencies(retdec retdec-project)
target_include_directories(retdec PUBLIC ${source_dir}/include)
target_link_libraries(retdec jsoncpp)
