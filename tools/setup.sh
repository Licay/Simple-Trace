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
# git apply $KERNEL_DIR/drivers/simple_trace/tools/kernel.diff
sed -i '0,/^$/s//source "drivers\/simple_trace\/Kconfig"\n/' $KERNEL_DIR/drivers/Kconfig
sed -i '0,/^$/s//obj-y\t\t\t\t+= simple_trace\/\n/' $KERNEL_DIR/drivers/Makefile
cd -

echo "Done! Kernel source is ready for Simple Trace."
