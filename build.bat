gcc -shared -o HookDLL.dll HookDLL.cpp -lminhook -s -static
gcc Loader.cpp -o Loader.exe -s -static -municode