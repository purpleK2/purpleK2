#!/bin/bash

set -e

LIBS_DIR=$1

# all libs
declare -a libs=("limine"
             "nanoprintf"
             "uacpi"
             )

# empty array for libs that have to be cloned
declare -a libs_to_clone=()
# empty array for libs that have to be updated
declare -a libs_to_update=()

check_if_cloned() {
    # check if the submodule dir contains a .git directory
    for lib in "${libs[@]}"; do
        if [ -d "$LIBS_DIR/$lib/.git" ]; then
            libs_to_update+=("$lib")
        else
            libs_to_clone+=("$lib")
        fi
    done
}

clone_libs() {
    # clone the libs
    for lib in "${libs_to_clone[@]}"; do
        echo "Cloning $lib..."
        git submodule update --init "$LIBS_DIR/$lib"
    done
}

update_libs() {
    # update the libs
    for lib in "${libs_to_update[@]}"; do
        echo "Updating $lib..."
        git submodule update --remote "$LIBS_DIR/$lib"
    done
}

check_if_cloned

if [ ${#libs_to_update[@]} -eq 0 ]; then
    echo "All libs are up to date."
else
    echo "The following libs need to be updated:"
    for lib in "${libs_to_update[@]}"; do
        echo "- $lib"
    done
fi

if [ ${#libs_to_clone[@]} -eq 0 ]; then
    echo "All libs are already cloned."
else
    echo "The following libs need to be cloned:"
    for lib in "${libs_to_clone[@]}"; do
        echo "- $lib"
    done
fi

clone_libs
update_libs

