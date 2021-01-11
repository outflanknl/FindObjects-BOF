BOF := FindProcHandle
BOF2 := FindModule
CC_x64 := x86_64-w64-mingw32-gcc

all:
	$(CC_x64) -o $(BOF).o -c $(BOF).c -masm=intel
	$(CC_x64) -o $(BOF2).o -c $(BOF2).c -masm=intel

clean:
	rm $(BOF).o
