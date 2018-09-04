## CMake build script for user guide.
##

find_package(LATEX REQUIRED)
find_package(LATEX COMPONENTS PDFLATEX REQUIRED)

# Configure and copy LaTeX source file.
configure_file("user_guide.tex" "${CMAKE_CURRENT_BINARY_DIR}/user_guide.tex" @ONLY)

add_custom_target(user-guide
	SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/user_guide.tex
	COMMENT "Generating user guide with LaTeX" VERBATIM
	# We need to copy all the sources to the working directory (CMAKE_CURRENT_BINARY_DIR).
	# Tha LaTeX source file is copied using configure_file().
	COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/figures" "${CMAKE_CURRENT_BINARY_DIR}/figures"
	# Compile the sources using pdflatex.
	COMMAND ${PDFLATEX_COMPILER} -draftmode user_guide.tex
	COMMAND ${PDFLATEX_COMPILER} user_guide.tex
	# Copy the result back to the source directory.
	COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/user_guide.pdf" "${CMAKE_CURRENT_SOURCE_DIR}")
