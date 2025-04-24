#!/bin/bash

# KERNEL_DIR=
# BRANCH=""

if [ -z "$KERNEL_DIR" ]; then
    KERNEL_DIR="./"
fi
KERNEL_DIR=$(realpath "$KERNEL_DIR")
if [ -z "$BRANCH" ]; then
    BRANCH="main"
fi

git clone https://github.com/Licay/Simple-Trace.git --branch $BRANCH $KERNEL_DIR/drivers/simple_trace

cd $KERNEL_DIR
git apply $KERNEL_DIR/drivers/simple_trace/tools/kernel.diff
cd -

echo "Done! Kernel source is ready for Simple Trace."
