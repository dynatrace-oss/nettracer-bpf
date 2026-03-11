## Building
Building process is verfied on Ubuntu 18.04 and Debian 12 bookworm

**Prerequisites**
* conan >= 1.66.0  but <= 2.*
* cmake >= 3.28.4
* clang >= 16
* libelf-dev
* linux-headers-4.15.*

Add a new remote:
```
conan remote add conancenter https://center.conan.io
```

**Build**

```
cmake -DCMAKE_BUILD_TYPE=<build type> -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -S . -B <build dir>
cmake --build <build dir>
```
