
## 使用方法

```bash
# you need set env: KERNEL_DIR
KERNEL_DIR=./ BRANCH=rc sh -c "$(curl -fsSL https://github.com/Licay/Simple-Trace/raw/refs/heads/rc/tools/setup.sh)"
```

快速移除
```bash
# you need set env: KERNEL_DIR
KERNEL_DIR=./
cd $KERNEL_DIR
rm drivers/simple_trace -rf
git checkout drivers/Kconfig drivers/Makefile
cd -
```
