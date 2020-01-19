include(ExternalProject)

ExternalProject_Add(retdec-project
	URL https://github.com/avast/retdec/archive/b0240726975a6b1b58c41f0bdeef64686374bfe0.zip
	URL_HASH SHA256=2c84409b56810378d83721655be1f913d72fd151963573dccdb5c4f04d5229d4
	# Disable the configure step.
        CONFIGURE_COMMAND ""	
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

set(RETDEC_SERDES_SOURCES
	${source_dir}/src/serdes/address.cpp
	${source_dir}/src/serdes/architecture.cpp
	${source_dir}/src/serdes/basic_block.cpp
	${source_dir}/src/serdes/calling_convention.cpp
	${source_dir}/src/serdes/class.cpp
	${source_dir}/src/serdes/file_format.cpp
	${source_dir}/src/serdes/file_type.cpp
	${source_dir}/src/serdes/function.cpp
	${source_dir}/src/serdes/language.cpp
	${source_dir}/src/serdes/object.cpp
	${source_dir}/src/serdes/pattern.cpp
	${source_dir}/src/serdes/std.cpp
	${source_dir}/src/serdes/storage.cpp
	${source_dir}/src/serdes/tool_info.cpp
	${source_dir}/src/serdes/type.cpp
	${source_dir}/src/serdes/utils.cpp
	${source_dir}/src/serdes/vtable.cpp
)
set(RETDEC_COMMON_SOURCES
	${source_dir}/src/common/address.cpp
	${source_dir}/src/common/architecture.cpp
	${source_dir}/src/common/basic_block.cpp
	${source_dir}/src/common/calling_convention.cpp
	${source_dir}/src/common/class.cpp
	${source_dir}/src/common/file_format.cpp
	${source_dir}/src/common/file_type.cpp
	${source_dir}/src/common/function.cpp
	${source_dir}/src/common/language.cpp
	${source_dir}/src/common/object.cpp
	${source_dir}/src/common/pattern.cpp
	${source_dir}/src/common/storage.cpp
	${source_dir}/src/common/tool_info.cpp
	${source_dir}/src/common/type.cpp
	${source_dir}/src/common/vtable.cpp
)
set(RETDEC_UTILS_SOURCES
	${source_dir}/src/utils/alignment.cpp
	${source_dir}/src/utils/byte_value_storage.cpp
	${source_dir}/src/utils/binary_path.cpp
	${source_dir}/src/utils/conversion.cpp
	${source_dir}/src/utils/dynamic_buffer.cpp
	${source_dir}/src/utils/file_io.cpp
	${source_dir}/src/utils/filesystem_path.cpp
	${source_dir}/src/utils/math.cpp
	${source_dir}/src/utils/memory.cpp
	${source_dir}/src/utils/string.cpp
	${source_dir}/src/utils/system.cpp
	${source_dir}/src/utils/time.cpp
)
set(RETDEC_CONFIG_SOURCES
	${source_dir}/src/config/base.cpp
	${source_dir}/src/config/config.cpp
	${source_dir}/src/config/parameters.cpp
)
set(WHEREAMI_SOURCES
	${source_dir}/deps/whereami/whereami.c
)

add_custom_command(OUTPUT
	${RETDEC_SERDES_SOURCES}
	${RETDEC_COMMON_SOURCES}
	${RETDEC_UTILS_SOURCES}
	${RETDEC_CONFIG_SOURCES}
	${WHEREAMI_SOURCES}
	DEPENDS retdec-project
)

# Add libraries.
add_library(retdec
	${RETDEC_SERDES_SOURCES}
	${RETDEC_COMMON_SOURCES}
	${RETDEC_UTILS_SOURCES}
	${RETDEC_CONFIG_SOURCES}
	${WHEREAMI_SOURCES}
)

add_dependencies(retdec retdec-project)
target_include_directories(retdec PUBLIC
	${source_dir}/include
	${source_dir}/src
	${source_dir}/deps
	${source_dir}/deps/whereami
)
target_link_libraries(retdec jsoncpp)
