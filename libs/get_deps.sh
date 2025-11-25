#!/bin/bash

set -e

# kernel source directory
KERNEL_DIR=$1
LIBS_DIR=$2

# required libraries
declare -a libs=("limine"
				 "nanoprintf"
                 "uacpi"
                 )

stderr_echo() { 
	echo "$@" >&2; 
}

check_submodule() {
	# has the submodule been cloned
	if [ ! -d "$1" ]; then
		# clone it
		printf "Downloading and "
		git submodule update --init "$1" >> /dev/null
	fi
	# update it
	printf "Updating module $1\n"
	git submodule update --remote "$1" >> /dev/null
	return 0
}

# $1: source file
# $2 target directory
copy_if_exists() {
	if [ ! -e "$1" ]; then
		stderr_echo "ERROR: file $1 does not exist. Quitting task..."
		return 1
	fi

	# parse everything after last slash
	LAST_SLASH=${2##*/}
	if [[ $LAST_SLASH == *"."* ]]; then
		DIRECTORY=${2//$LAST_SLASH}	# remove the last part if it's a file...
	else
		DIRECTORY=$2
	fi

	# ...to create the parent directory
	if [ ! -d "$DIRECTORY" ]; then
		stderr_echo "target directory $DIRECTORY not found. Creating it..."
		mkdir -p "$DIRECTORY"
	fi

	echo "--> Copying: $1"
	echo "	  to: $2"
	cp -fr "$1" "$2"
}

if [ -z "$KERNEL_DIR" ]; then
	stderr_echo "ERROR: You must give the ABSOLUTE path of your kernel source code directory (eg. src)."
	exit 1
fi

forbidden_prefix="/"

if [ -z "$LIBS_DIR" ] || [[ "$LIBS_DIR" == "/"* ]]; then
	stderr_echo "ERROR: You must give the RELATIVE path of the external libraries (eg. libs)."
	exit 1
fi

LIBS_FULL_DIR="$PWD/$LIBS_DIR"

# check if submodules have been downloaded
for lib in "${libs[@]}"
do
	check_submodule "$LIBS_FULL_DIR/$lib"
done

# copy limine
copy_if_exists $LIBS_DIR/limine/limine.h $KERNEL_DIR/system/limine.h

# copy npf
copy_if_exists $LIBS_DIR/nanoprintf/nanoprintf.h $KERNEL_DIR/system/nanoprintf.h

# copy uACPI
# NOTE: very wacky, must make it better
copy_if_exists $LIBS_DIR/uacpi/include/uacpi $KERNEL_DIR/acpi
UACPI_BASE_PATH="$LIBS_FULL_DIR/uacpi"
for uacpi_c in "$UACPI_BASE_PATH/source/"*; do
    if [[ "$uacpi_c" == *".c" ]]; then
        # printf "$uacpi_c\n"
        copy_if_exists $uacpi_c $KERNEL_DIR/acpi/uacpi
    fi
done
