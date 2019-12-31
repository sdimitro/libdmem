# libdmem

Attach the library to a program during loading at runtime with `LD_PRELOAD`:
```
$ DMEM_OPTS=trace-stderr,log-allocs LD_PRELOAD=./libdmem.so ls
```
