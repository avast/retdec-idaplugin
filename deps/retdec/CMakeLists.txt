include(ExternalProject)

ExternalProject_Add(retdec-project
	URL https://github.com/avast/retdec/archive/182a55e64dc15e10c8672b7be4b1f6bc9702214b.zip
	URL_HASH SHA256=d98726f2d04f71da5246a286bdca5d908da56334179f786c2dc299ee61417cc4
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

add_library(rapidjson INTERFACE)
target_include_directories(rapidjson
	SYSTEM INTERFACE
		${source_dir}/deps/rapidjson/include
)
target_compile_definitions(rapidjson
	INTERFACE
		RAPIDJSON_HAS_STDSTRING=1
		RAPIDJSON_HAS_CXX11_RVALUE_REFS=1
)

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
target_link_libraries(retdec rapidjson)
