
if(RETDEC_LOCAL_DIR)
	message(STATUS "RetDec: using local RetDec directory.")
	add_subdirectory(
		${RETDEC_LOCAL_DIR}
		${CMAKE_CURRENT_BINARY_DIR}/retdec-build
		EXCLUDE_FROM_ALL
	)
	set(retdec_SOURCE_DIR ${RETDEC_LOCAL_DIR})
else()
	message(STATUS "RetDec: using remote RetDec revision.")
	include(FetchContent)

	FetchContent_Declare(retdec
		GIT_REPOSITORY https://github.com/avast/retdec
		GIT_TAG        c1ecff3c0c9b494e89f918595dc00d2bce336ac2
	)

	FetchContent_GetProperties(retdec)
	if(NOT retdec_POPULATED)
		FetchContent_Populate(retdec)
		add_subdirectory(
			${retdec_SOURCE_DIR}
			${retdec_BINARY_DIR}
			EXCLUDE_FROM_ALL
		)
	endif()
endif()

if(IDA_PATH)
	install(
		DIRECTORY
			"${retdec_SOURCE_DIR}/support/ordinals"
			"${retdec_SOURCE_DIR}/support/yara_patterns"
			"${retdec_SOURCE_DIR}/support/types"
		DESTINATION
			"${IDA_PATH}/plugins/retdec/"
	)
endif()

set(retdec_SOURCE_DIR ${retdec_SOURCE_DIR} PARENT_SCOPE)
