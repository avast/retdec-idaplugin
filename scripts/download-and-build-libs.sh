#!/bin/bash
#
# Downloads, builds, and install libraries that our IDA plugin needs during its
# build.
#
# The script works on Linux (GCC) and Windows (GCC or MSVC via MSYS).
#

#
# System.
#
if [[ "$(uname -s)" == *Linux* ]]; then
	SYS="linux"
elif [[ "$(uname -s)" == *MINGW* ]] || [[ "$(uname -s)" == *MSYS* ]]; then
	SYS="windows"
fi

#
# Settings.
#
SCRIPT_DIR="$(cd "$(dirname "$0")"; pwd -P)"
IDA_LIBS_DIR="$(readlink -f "$SCRIPT_DIR/../../../idaplugin-libs")"
CPUS=$(nproc)
COMPILER="gcc"
MAKE="make"
export CFLAGS="-m32 -w"
export CXXFLAGS="-m32 -w"

#
# Argument handling.
#
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
	echo "Usage: $0 [OPTIONS]"
	echo ""
	echo "Downloads, builds, and install libraries that our IDA plugin needs."
	echo ""
	echo "Options:"
	echo ""
	echo "  -c COMPILER, --compiler COMPILER"
	echo "      Compiler to be used. Default: $COMPILER. Available compilers: gcc, msvc."
	echo ""
	echo "Target directory: $IDA_LIBS_DIR"
	exit 1
elif [ "$1" = "-c" ] || [ "$1" = "--compiler" ]; then
	if [ -z "$2" ]; then
		echo "error: missing argument for $1" >&2
		exit 1
	elif [ "$2" != "gcc" ] && [ "$2" != "msvc" ]; then
		echo "error: unsupported compiler: $2" >&2
		exit 1
	fi
	COMPILER="$2"
fi

# Select a proper CMake generator and make program.
if [ "$SYS" = "linux" ]; then
	CMAKE_GENERATOR="Unix Makefiles"
elif [ "$SYS" = "windows" ]; then
	if [ "$COMPILER" = "gcc" ]; then
		CMAKE_GENERATOR="MSYS Makefiles"
	else # MSVC
		CMAKE_GENERATOR="NMake Makefiles JOM"
		MAKE="jom"
	fi
fi

#
# Initialization.
#
mkdir -p "$IDA_LIBS_DIR" || exit 1
cd "$IDA_LIBS_DIR" || exit 1

#
# JsonCPP (https://github.com/open-source-parsers/jsoncpp)
#
if [ ! -d "jsoncpp" ]; then
	rm -rf "jsoncpp-1.6.5" || exit 1
	if [ ! -f "jsoncpp-1.6.5.zip" ]; then
		# --no-check-certificate is for Windows.
		wget "https://github.com/open-source-parsers/jsoncpp/archive/1.6.5.zip" \
			--no-check-certificate -O "jsoncpp-1.6.5.zip" || exit 1
	fi
	echo "Extracting jsoncpp-1.6.5.zip"
	unzip -q "jsoncpp-1.6.5.zip" || exit 1
	cd "jsoncpp-1.6.5" || exit 1
	mkdir "build" || exit 1
	cd "build" || exit 1
	cmake .. \
		-G"$CMAKE_GENERATOR" \
		-DJSONCPP_WITH_TESTS=0 \
		-DJSONCPP_WITH_POST_BUILD_UNITTEST=0 \
		-DJSONCPP_WITH_PKGCONFIG_SUPPORT=0 \
		-DBUILD_SHARED_LIBS=0 \
		-DBUILD_STATIC_LIBS=1 \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_INSTALL_PREFIX:PATH="$(readlink -f ../../jsoncpp)" || exit 1
	$MAKE -j "$CPUS" VERBOSE=1 || exit 1
	$MAKE install || exit 1
	cd ../.. || exit 1
	rm -rf "jsoncpp-1.6.5.zip" "jsoncpp-1.6.5" || exit 1
else
	echo "* jsoncpp has already been installed; skipping"
fi

#
# Boost (http://www.boost.org/)
#
if [ ! -d "boost" ]; then
	if [ "$COMPILER" = "gcc" ]; then
		rm -rf "boost_1_59_0" || exit 1
		if [ ! -f "boost_1_59_0.tar.gz" ]; then
			wget "http://downloads.sourceforge.net/project/boost/boost/1.59.0/boost_1_59_0.tar.gz" \
				|| exit 1
		fi
		echo "Extracting boost_1_59_0.tar.gz"
		tar xf "boost_1_59_0.tar.gz" || exit 1
		cd "boost_1_59_0" || exit 1
		if [ "$SYS" = "linux" ]; then
			# According to Peter, GCC on Linux generates libraries that crash IDA,
			# so we have to use Clang.
			BOOST_TOOLSET="clang"
			BOOST_BOOTSTRAP="./bootstrap.sh"
		elif [ "$SYS" = "windows" ]; then
			BOOST_TOOLSET="gcc"
			BOOST_BOOTSTRAP="./bootstrap.bat"
		fi
		$BOOST_BOOTSTRAP \
			--with-toolset="$BOOST_TOOLSET" \
			--prefix="$(readlink -f ../boost)" || exit 1
		./b2 \
			variant=release \
			debug-symbols=off \
			runtime-link=static \
			link=static \
			toolset="$BOOST_TOOLSET" \
			address-model=32 \
			cxxflags="-m32 -O2 -w" \
			linkflags="-m32" \
			define=BOOST_SYSTEM_NO_DEPRECATED \
			threading=multi \
			--layout=system \
			--prefix="$(readlink -f ../boost)" \
			--with-atomic \
			--with-date_time \
			--with-filesystem \
			--with-program_options \
			--with-regex \
			--with-system \
			--with-test \
			--with-thread \
			-j "$CPUS" install || exit 1
		cd .. || exit 1
		rm -rf "boost_1_59_0.tar.gz" "boost_1_59_0" || exit 1
	else # MSVC
		# Download pre-built binaries, i.e. we do not need to build Boost from
		# scratch.
		# We have to download the msvc-all package because it is the only one
		# that is an archive, not an .exe installer. The downside is that the
		# msvc-all package is approx. 1.6 GB big...
		if [ ! -f "boost_1_59_0-bin-msvc-all-32-64.7z" ]; then
			wget "http://downloads.sourceforge.net/project/boost/boost-binaries/1.59.0/boost_1_59_0-bin-msvc-all-32-64.7z" \
				|| exit 1
		fi
		echo "Extracting boost_1_59_0-bin-msvc-all-32-64.7z"
		7z x "boost_1_59_0-bin-msvc-all-32-64.7z" > /dev/null || exit 1
		# Copy only the needed directories/files and remove the rest.
		mkdir -p "boost" "boost/include" "boost/lib" || exit 1
		mv "boost_1_59_0/boost" "boost/include" || exit 1
		mv "boost_1_59_0/lib32-msvc-14.0"/libboost_*-vc140-mt-1_59.lib "boost/lib" || exit 1
		rm -rf "boost_1_59_0-bin-msvc-all-32-64.7z" "boost_1_59_0" || exit 1
	fi
else
	echo "* boost has already been installed; skipping"
fi

#
# OpenSSL (https://www.openssl.org)
#
if [ ! -d "openssl" ]; then
	if [ "$COMPILER" = "gcc" ]; then
		rm -rf "openssl-1.0.2d" || exit 1
		if [ ! -f "openssl-1.0.2d.tar.gz" ]; then
			# --no-check-certificate is for Windows.
			wget "https://www.openssl.org/source/openssl-1.0.2d.tar.gz" \
				--no-check-certificate || exit 1
		fi
		echo "Extracting openssl-1.0.2d.tar.gz"
		tar xf "openssl-1.0.2d.tar.gz" || exit 1
		cd "openssl-1.0.2d" || exit 1
		if [ "$SYS" = "linux" ]; then
			# Windows (MSYS) does not provide 'setarch', it is only on Linux.
			SETARCH="setarch i386"
		fi
		$SETARCH ./config -m32 \
			--prefix="$(readlink -f ../openssl)" || exit 1
		$MAKE -j "$CPUS" || exit 1
		$MAKE install || exit 1
		cd .. || exit 1
		rm -rf "openssl/lib"/{engines,pkgconfig} || exit 1
		rm -rf "openssl"/{bin,ssl} || exit 1
		rm -rf "openssl-1.0.2d.tar.gz" "openssl-1.0.2d" || exit 1
		# There is a problem in FindOpenSSL.cmake on Debian, where version
		# detection does not work when there is a space between '#' and 'define' in
		# include/openssl/opensslv.h. We need to remove the space to make it work.
		sed -i 's/^# define /#define /' "openssl/include/openssl/opensslv.h"
	else # MSVC
		# Download pre-built binaries, i.e. we do not need to build OpenSSL from
		# scratch.
		if [ ! -f "openssl-1.0.2d-vs2015.7z" ]; then
			wget "http://www.npcglib.org/~stathis/downloads/openssl-1.0.2d-vs2015.7z" || exit 1
		fi
		echo "Extracting openssl-1.0.2d-vs2015.7z"
		7z x "openssl-1.0.2d-vs2015.7z" > /dev/null || exit 1
		# Copy only the needed directories/files and remove the rest.
		mkdir -p "openssl" || exit 1
		mv "openssl-1.0.2d-vs2015/"{include,lib} "openssl" || exit 1
		rm -rf "openssl-1.0.2d-vs2015" "openssl-1.0.2d-vs2015.7z"
	fi
else
	echo "* openssl has already been installed; skipping"
fi

#
# cpp-netlib (http://cpp-netlib.org/)
#
if [ ! -d "cpp-netlib" ]; then
	rm -rf "cpp-netlib-0.11.2-final" || exit 1
	if [ ! -f "cpp-netlib-0.11.2-final.zip" ]; then
		wget "http://downloads.cpp-netlib.org/0.11.2/cpp-netlib-0.11.2-final.zip" \
			|| exit 1
	fi
	echo "Extracting cpp-netlib-0.11.2-final.zip"
	unzip -q "cpp-netlib-0.11.2-final.zip" || exit 1
	cd "cpp-netlib-0.11.2-final" || exit 1
	mkdir "build" || exit 1
	cd "build" || exit 1
	cmake .. \
		-G"$CMAKE_GENERATOR" \
		-DBOOST_ROOT="$(readlink -f ../../boost)" \
		-DBOOST_LIBRARYDIR="$(readlink -f ../../boost/lib)" \
		-DBoost_USE_STATIC_LIBS=1 \
		-DOPENSSL_ROOT_DIR="$(readlink -f ../../openssl)" \
		-DCPP-NETLIB_BUILD_TESTS:BOOL=OFF \
		-DCPP-NETLIB_BUILD_EXAMPLES:BOOL=OFF \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_INSTALL_PREFIX:PATH="$(readlink -f ../../cpp-netlib)" || exit 1
	$MAKE -j "$CPUS" VERBOSE=1 || exit 1
	$MAKE install || exit 1
	cd ../.. || exit 1
	rm -rf "cpp-netlib/lib/"{CMake,cmake} || exit 1
	rm -rf "cpp-netlib-0.11.2-final.zip" "cpp-netlib-0.11.2-final" || exit 1
else
	echo "* cpp-netlib has already been installed; skipping"
fi

#
# retdec-cpp (https://github.com/s3rvac/retdec-cpp)
#
if [ ! -d "retdec-cpp" ]; then
	rm -rf "retdec-cpp-0.1" || exit 1
	if [ ! -f "retdec-cpp.zip" ]; then
		# --no-check-certificate is for Windows.
		wget "https://github.com/s3rvac/retdec-cpp/archive/0.1.zip" \
			--no-check-certificate -O "retdec-cpp.zip" || exit 1
	fi
	echo "Extracting retdec-cpp.zip"
	unzip -q "retdec-cpp.zip" || exit 1
	cd "retdec-cpp-0.1" || exit 1
	mkdir "build" || exit 1
	cd "build" || exit 1
	cmake .. \
		-G"$CMAKE_GENERATOR" \
		-DBOOST_ROOT="$(readlink -f ../../boost)" \
		-DBOOST_LIBRARYDIR="$(readlink -f ../../boost/lib)" \
		-DBoost_USE_STATIC_LIBS=1 \
		-DCPPNETLIB_ROOT="$(readlink -f ../../cpp-netlib)" \
		-DOPENSSL_ROOT_DIR="$(readlink -f ../../openssl)" \
		-DJsonCpp_ROOT_DIR="$(readlink -f ../../jsoncpp)" \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_INSTALL_PREFIX:PATH="$(readlink -f ../../retdec-cpp)" || exit 1
	$MAKE -j "$CPUS" VERBOSE=1 || exit 1
	$MAKE install || exit 1
	cd ../.. || exit 1
	rm -rf "retdec-cpp/CMake" || exit 1
	rm -rf "retdec-cpp/lib/cmake" || exit 1
	rm -rf "retdec-cpp.zip" "retdec-cpp-0.1" || exit 1
else
	echo "* retdec-cpp has already been installed; skipping"
fi

echo ""
echo "Done!"
