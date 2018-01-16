#!/bin/bash
#
# The script decompiles the given file via RetDec IDA plugin.
# The supported decompilation modes are:
#    full   - decompile entire input file.
#    select - decompile only the function selected by the given address.
#

SCRIPT_FULL="retdec-decompile-full.idc"
SCRIPT_SELECT="retdec-decompile-selective.idc"

SCRIPT_NAME=$0
SCRIPTPATH="$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )"

#
# Print help.
#
print_help()
{
	echo "Decompiles the given file via RetDec IDA plugin."
	echo ""
	echo "Usage:"
	echo "    $0 [ options ] -i path file"
	echo ""
	echo "Options:"
	echo "    -i path    --ida path                         Path to the IDA directory. You can also specify it via the IDA_PATH environment variable."
	echo "    -d file,   --idb file                         IDA DB file associated with input file."
	echo "    -f,        --full                             Decompile entire input file. Default mode."
	echo "    -g,        --debug                            Debug run - IDA's and RetDec's outputs are dumped into stdout. If Exit(X) is removed from IDC scripts, it hangs in IDA."
	echo "    -h,        --help                             Print this help message."
	echo "    -o file,   --output file                      Output file (default: file.c). All but the last component must exist."
	echo "    -s addr,   --select addr                      Decompile only the function selected by the given address (any address inside function). Examples: 0x1000, 4096."
}

GETOPT_SHORTOPT="i:d:fgho:s:"
GETOPT_LONGOPT="ida:,idb:,full,debug,help,output:,select:"

#
# Dump all important variables.
#
print_variables()
{
	echo "mode     = $MODE"
	echo "selected = $SELECTED"
	echo "input    = $IN"
	echo "cp input = $IN_NEW"
	echo "idb      = $IDB"
	echo "output   = $OUT"
	echo "out dir  = $OUT_DIR"
}

#
# Print error message to stderr and die.
# 1 argument is needed
# Returns - 1 if number of arguments is incorrect
#
print_error_and_die()
{
	if [ "$#" != "1" ]; then
		exit 1
	fi
	echo "Error: $1" >&2
	exit 1
}

#
# Detect OS type (win / linux)
#
get_SYS()
{
	case "$(uname -s)" in
		*Linux*)
			echo "linux"
			;;
		*Windows*|*CYGWIN*|*MINGW*|*MSYS*)
			echo "windows"
			;;
		*)
			echo "unknown"
			;;
	esac
}

SYS="$(get_SYS)"
if [ "$SYS" != "windows" -a "$SYS" != "linux" ]; then
	echo "Error: Cannot detect OS type: $(uname -s)" >&2
	exit 1
fi

# These variables are used in the program.
MODE=""
SELECTED=""
IN=""
IDB=""
OUT=""
DEBUG=""
IDA_DIR="$IDA_PATH" # The path to IDA can be optionally specified in an environment variable.
IDAL=""

#
# Check proper combination of input arguments.
#
check_arguments()
{
	# Check whether the input file was specified.
	if [ -z "$IN" ]; then
		print_error_and_die "No input file was specified"
	fi

	# Check whether the path to IDA was specified.
	if [ -z "$IDA_DIR" ]; then
		print_error_and_die "No path to IDA directory was specified"
	fi

	# Check whether the path to IDA is a directory.
	if [ ! -d "$IDA_DIR" ]; then
		print_error_and_die "The path to IDA '$IDA_DIR' is not a directory"
	fi

	# Check whether IDAL file exists.
	if [ ! -f "$IDAL" ]; then
		print_error_and_die "The IDA executable '$IDAL' does not exist"
	fi

	# Check whether the input file exists.
	if [ ! -r "$IN" ]; then
		print_error_and_die "The input file '$IN' does not exist or is not readable"
	fi

	# Check whether specified IDA DB file exists.
	if [ "$IDB" ] && [ ! -r "$IDB" ]; then
		print_error_and_die "Specified IDA DB file does not exist or is not readable"
	fi

	# If output specified, path must be valid -- all but the last file must exist.
	if [ "$OUT" ] && [ ! -r "$(dirname "$OUT")" ]; then
		print_error_and_die "The output path '$OUT' is not valid"
	fi
}

# Check script arguments.
PARSED_OPTIONS=$(getopt -o "$GETOPT_SHORTOPT" -l "$GETOPT_LONGOPT" -n "$SCRIPT_NAME" -- "$@")

# Bad arguments.
[ $? -ne 0 ] && print_error_and_die "Getopt - parsing parameters fail"

eval set -- "$PARSED_OPTIONS"

while true ;
do
	case "$1" in
	-i|--ida)
		[ "$IDA_DIR" ] && print_error_and_die "Duplicate option: -i|--ida"
		IDA_DIR=$2
		shift 2;;
	-d|--idb)
		[ "$IDB" ] && print_error_and_die "Duplicate option: -d|--idb"
		IDB=$2
		shift 2;;
	-f|--full)
		[ "$MODE" ] && print_error_and_die "Duplicate mode option: -f|--full or -s|--select"
		MODE="full"
		shift;;
	-g|--debug)
		[ "$DEBUG" ] && print_error_and_die "Duplicate mode option: -g|--debug"
		DEBUG="debug"
		shift;;
	-h|--help)
		print_help
		exit 0;;
	-o|--output)
		[ "$OUT" ] && print_error_and_die "Duplicate option: -o|--output"
		OUT=$2
		shift 2;;
	-s|--select)
		[ "$MODE" ] && print_error_and_die "Duplicate mode option: -f|--full or -s|--select"
		[ "$SELECTED" ] && print_error_and_die "Duplicate option: -s|--select"
		MODE="select"
		SELECTED=$2
		shift 2;;
	--) # Input file.
		if [ $# -eq 2 ]; then
			IN="$2"
		elif [ $# -gt 2 ]; then # Invalid options.
			print_error_and_die "Invalid options: '$2', '$3' ..."
		fi
		break;;
	esac
done

if [ "$SYS" = "win" ]; then
	IDAL="$IDA_DIR/idaw.exe"
else # Linux
	IDAL="$IDA_DIR/idal"
fi

# Check arguments and set default values for unset options.
check_arguments

# Full decompilation is the default mode --- it is used if no other mode was selected.
[ ! "$MODE" ] && MODE="full"

# If output not specified, set default output.
[ ! "$OUT" ] && OUT="$IN.c"

# Convert to absolute paths.
IN=$(readlink -f "$IN")
OUT=$(readlink -f "$OUT")
IDB=$(readlink -f "$IDB")

# Get directories.
OUT_DIR="$(dirname "$OUT")"

# Check that the decompilation script is reachable from PATH (the plugin requires that).
# When the decompilation script is not reachable from PATH, the plugin would fail, and
# since we are discarding the plugin's output, debugging of this problem would
# be very hard. To this end, when the decompilation script is not reachable from PATH,
# we update PATH to make it reachable.
if ! hash "retdec-decompiler.sh" &> /dev/null; then
	echo "error: The plugin requires retdec-decompiler.sh to be reachable from PATH." >&2
	echo "       You have to properly adjust your PATH before running this script." >&2
	exit 1
fi

# Check that the IDA license agreement has been done. Otherwise, $IDAL just
# hangs without any output and the script has to be manually terminated.
#
# The following check works only on Linux (I have no idea how the licence
# agreement works on Windows).
if [ "$SYS" = "linux" ]; then
	IDA_REG_FILE="$HOME/.idapro/ida.reg"
	if [ ! -f "$IDA_REG_FILE" ]; then
		echo "error: You have not agreed to the IDA Pro license before using this script." >&2
		echo "       To do that, run the following command and agree to the license:" >&2
		echo "" >&2
		echo "       $IDAL" >&2
		echo "" >&2
		exit 1
	fi
fi

# $IDAL requires the TERM environment variable to be set, which is not true
# when this script runs from cron/at (e.g. via regression tests). Therefore,
# force a terminal to make $IDAL happy.
# The terminal cannot be 'dumb', which is the value set by cron.
if [ -z "$TERM" ] || [ "$TERM" = "dumb" ]; then
	export TERM=xterm
fi

# $IDAL does not work inside screen/tmux with terminal other than 'xterm', so
# if the script is running inside screen/tmux, force a proper TERM for $IDAL.
# The check below is based on http://serverfault.com/a/377225
if [ -n "$STY" ] || [ -n "$TMUX" ]; then
	export TERM=xterm
fi

# Copy inputs to output directory.
[ "$(dirname "$IN")" != "$OUT_DIR" ] && cp "$IN" "$OUT_DIR"
[ "$IDB" ] && [ "$(dirname "$IDB")" != "$OUT_DIR" ] && cp "$IDB" "$OUT_DIR"
IN_NEW="$OUT_DIR/$(basename "$IN")"

# On Windows, we need to convert the path to the input file from "/c/XYZ" to
# "c:/XYZ". Otherwise, the plugin will use Linux paths and fail to read/write
# files (e.g. the JSON configuration file that is the input to the decompilation script,
# see #1485).
if [ "$SYS" = "win" ] && [ "${IN_NEW:0:1}" = "/" ]; then
	IN_NEW="$(sed 's/^\/\([a-zA-Z]\)\//\1:\//' <<< "$IN_NEW")"
fi

# Debug dump.
#print_variables

RET=1

# Run IDA decompilation.
if [ "$MODE" = "full" ]; then
	if [ "$DEBUG" ]; then
		$IDAL -A -S"$SCRIPT_FULL \"$IN_NEW\" --debug" "$IN_NEW"
		RET=$?
	elif [ "$SYS" = "win" ]; then
		echo "$IDAL -A -S\"$SCRIPT_FULL '$IN_NEW' --debug\" \"$IN_NEW\""
		$IDAL -A -S"$SCRIPT_FULL \"$IN_NEW\"" "$IN_NEW"
		RET=$?
	else
		echo "$IDAL -A -S\"$SCRIPT_FULL '$IN_NEW' --debug\" \"$IN_NEW\""
		# We have to use script (http://stackoverflow.com/a/1402389).
		script -e -c "$IDAL -A -S\"$SCRIPT_FULL '$IN_NEW'\" \"$IN_NEW\"" "${IN_NEW}.idal.log" &> /dev/null
		RET=$?
	fi
elif [ "$MODE" = "select" ]; then
	if [ "$DEBUG" ]; then
		$IDAL -A -S"$SCRIPT_SELECT \"$IN_NEW\" $SELECTED --debug" "$IN_NEW"
		RET=$?
	elif [ "$SYS" = "win" ]; then
		echo "$IDAL -A -S\"$SCRIPT_SELECT '$IN_NEW' $SELECTED --debug\" \"$IN_NEW\""
		$IDAL -A -S"$SCRIPT_SELECT \"$IN_NEW\" $SELECTED" "$IN_NEW"
		RET=$?
	else
		echo "$IDAL -A -S\"$SCRIPT_SELECT '$IN_NEW' $SELECTED --debug\" \"$IN_NEW\""
		# We have to use script (http://stackoverflow.com/a/1402389).
		script -e -c "$IDAL -A -S\"$SCRIPT_SELECT '$IN_NEW' $SELECTED\" \"$IN_NEW\"" "${IN_NEW}.idal.log" &> /dev/null
		RET=$?
	fi
fi

# IDA decompilation produces "<input>.c" in any mode.
# Now we copy this file to desired output file.
[ -f "$IN_NEW.c" ] && [ "$IN_NEW.c" != "$OUT" ] && cp "$IN_NEW.c" "$OUT"

exit $RET
