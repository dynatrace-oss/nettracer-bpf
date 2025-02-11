## Building

**Prerequisites**
* conan >= 1.62.0
* cmake >= 3.22.3
* clang >= 16

Add a new remote:
```
conan remote add conancenter https://center.conan.io
```

**Build**

```
cmake -DCMAKE_BUILD_TYPE=<build type> -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -S . -B <build dir>
cmake --build <build dir>
```


**Alternate build in docker container**

If you wish to make Docker handle the whole setup, install Docker and run:

```
make
```

The project will be built, tested and the resulting binaries will be placed in _build_ directory.

Subsequently you can reuse created container for building and testing by using following commands:

```
make build-project
make test-project
