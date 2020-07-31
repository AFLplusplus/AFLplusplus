# Fuzzing Fuzzgoat with AFL++

## AFL

AFL - American Fuzzy Lop
Developed by - Michal Zalewski
For installing afl++
```
git clone ​ https://github.com/AFLplusplus/AFLplusplus.git
```
```
make
```
```
sudo make install
```
   
## What it Fuzzgoat?

A vulnerable C program that is used for testing fuzzers.

## Download the source of fuzzgoat with:
````
git clone  https://github.com/fuzzstati0n/fuzzgoat.git
````
![1](https://user-images.githubusercontent.com/44070827/89029646-8759b580-d34c-11ea-85f4-585c59da670d.png)



## Building Fuzzgoat:-
Go to the path of fuzzgoat and the build it with make.
 {in this case fuzzgoat is located at Desktop/fuzzing/fuzzgoat}
![2](https://user-images.githubusercontent.com/44070827/89029787-c982f700-d34c-11ea-9a06-deb5c17f413a.png) 


  

## Get Set Fuzz!!

For output create a out folder.
````
mkdir out
````

````
afl-fuzz -i in -o out ./fuzzgoat @@
````
● -i in Input Directory
● -o out Output Directory
● ./fuzzgoat -Binary to fuzz
● @@ -Is used for marking location in the targets command line where the input file should be in placed
![3](https://user-images.githubusercontent.com/44070827/89029803-d1429b80-d34c-11ea-9e76-2cc439898d69.png)
<span style="color: green">The basic tests and checks before fuzzer start. </span>



## Fuzzing and analysing the crashes:
![4](https://user-images.githubusercontent.com/44070827/89029806-d273c880-d34c-11ea-96b7-f694b3d5aa41.png)
<span style="color: green">3 cycles,total path,27 unique crashes were found </span>
#### Data under out(output) directory:
 
![image5](https://user-images.githubusercontent.com/44070827/89030480-2f23b300-d34e-11ea-924f-184bd86b371e.png)

#### Data under crashes:
![6](https://user-images.githubusercontent.com/44070827/89030514-4367b000-d34e-11ea-837c-b9e3e6c5284c.png)


#### .triage_crashes.sh:-

Using `.triage_crashes.sh` to analyse the crashes from the output
directory.
For this goto to the location where afl in installed
Then goto to experimental/crash_triage/
![7](https://user-images.githubusercontent.com/44070827/89030547-54182600-d34e-11ea-94bc-199d3abd9c1e.png)
``` 
./triage_crashes.sh /root/Desktop/fuzzing/fuzzgoat/out/ root/Desktop/fuzzing/fuzzgoat/fuzzgoat 
```
![8](https://user-images.githubusercontent.com/44070827/89030637-7ca02000-d34e-11ea-87b3-0b663806c23e.png)


#### Running crashes directly:-

```
./fuzzgoat/out/crashes/id:000025,sig:11,src:000116,time:166949,op:arith8,
pos:37,val:-5
```
{id can be anything depending on which crash you want to analyse}
![9](https://user-images.githubusercontent.com/44070827/89030700-a0636600-d34e-11ea-87cd-63de7d00e5cd.png)

#### Analysing crash via GDB:-

````
gdb ./fuzzgoat
````
![10](https://user-images.githubusercontent.com/44070827/89030738-bb35da80-d34e-11ea-9fd9-933a75d08276.png)
````
(gdb) run out/crashes/id:000025,sig:11,src:000116,time:166949,op:arith8,pos:37,val:5
````


![12](https://user-images.githubusercontent.com/44070827/89030742-bcff9e00-d34e-11ea-9a44-0b243b75db4a.png)


This is the cause for the segmentation fault.



