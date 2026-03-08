# HookLoader

## 功能

本程序通过hook和DLL注入拦截程序的注册表操作，重定向至本地文件中（运行时在内存中进行操作）

## 编译步骤

本项目使用了minhook库（ https://github.com/TsudaKageyu/minhook )，首先需要安装minhook库或者修改代码进行静态编译

（使用MSYS2可直接使用pacman命令安装，具体版本查看 https://packages.msys2.org/base/mingw-w64-MinHook ）

安装CMake

使用git clone或直接下载代码，打开代码目录下的命令行

输入

``` cmd
:: 如果使用的是MinGW
cmake -B build -DCMAKE_BUILD_TYPE=Release -G "MinGW Makefiles"
cmake --build build --parallel 8
```

或者如果使用的是非MinGW编译器的，输入

``` cmd
cmake -G
```

查找自己有的编译器，将`"MinGW Makefiles"`替换为对应的编译器

编译完成后在代码目录的`bin`文件夹下会生成`HookDLL.dll`和`Loader.exe`

## 使用方法

将`HookDLL.dll`和`Loader.exe`复制到别的软件目录下，直接将软件的主程序拖到`Loader.exe`上运行。

或者如果需要带参运行，打开命令行然后输入

``` cmd
Loader.exe [Loader参数] <命令/程序exe> <参数>
```

程序结束后，虚拟注册表会默认会保存到 `reg.dat` 文件中（使用-RF参数可用更改）

即可

## ！！注意！！

本程序仅在 64位 Win11 上进行过测试，打开的是64位的exe，且还未完全完成（还需要hook几个API）

## 代办

- [x] 完全hook注册表API
- [x] 支持更多可选参数（更改注册表文件保存路径等）
- [ ] 支持重定向文件操作
- [ ] 支持物理注册表互通