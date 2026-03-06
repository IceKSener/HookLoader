g++ -shared -o HookDLL.dll HookDLL.cpp -lminhook -s -static -Wl,--image-base=0x66000000
g++ Loader.cpp VirtualRegistry.cpp -o Loader.exe -s -static -municode