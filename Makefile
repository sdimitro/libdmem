all: driver libdmem.so

driver: driver.c
	${CC} -g -O3 $< -o $@

libdmem.so: dmem.c
	${CC} -g -fno-omit-frame-pointer -Wall -D_GNU_SOURCE -O3 -std=c11 -shared -fPIC $< -o $@ -ldl
