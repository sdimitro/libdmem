# libdmem

Attach the library to a program during loading at runtime with `LD_PRELOAD`:
```
$ DMEM_OPTS=log-all LD_PRELOAD=./libdmem.so ls
```
