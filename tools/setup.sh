#!/bin/bash

KERNEL_DIR=$1
if [ -z "$KERNEL_DIR" ]; then
    echo "Usage: $0 <kernel_dir>"
    exit 1
fi
KERNEL_DIR=$(realpath "$KERNEL_DIR")
RC=$2
BRANCH=""
if [ $2 = "rc" ]; then
    BRANCH="rc"
else
    BRANCH="main"
fi

git clone https://github.com/Licay/Simple-Trace.git --branch $BRANCH $KERNEL_DIR/drivers/simple_trace

cd $KERNEL_DIR
git apply $KERNEL_DIR/drivers/simple_trace/tools/kernel.diff
cd -

echo "Done! Kernel source is ready for Simple Trace."
