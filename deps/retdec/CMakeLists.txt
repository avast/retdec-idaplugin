
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
		GIT_TAG        c5b0374a381d7b5bd1dd540fa9918cc7e7dfe094
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

if(IDA_DIR)
	install(
		DIRECTORY
			"${retdec_SOURCE_DIR}/support/ordinals"
			"${retdec_SOURCE_DIR}/support/yara_patterns"
			"${retdec_SOURCE_DIR}/support/types"
		DESTINATION
			"${IDA_DIR}/plugins/retdec/"
	)
endif()

set(retdec_SOURCE_DIR ${retdec_SOURCE_DIR} PARENT_SCOPE)
