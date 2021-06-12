# How to troubleshoot AFL++'s wine mode

## 1) Debugging
To turn on wine debugging use the `WINEDEBUG` environment variable, 
e.g. `WINEDEBUG=+timestamp,+tid,+loaddll`. 

## 2) LoadLibraryA workaround
The forked process fails to load libraries loaded via `LoadLibrary` 
if the load happens after the entry point (error code: 87). To resolve 
this issue, one needs to load any external libraries before the fork happens.

An early DLL load can be achieved by adding the DLL name into the `Import Directory`
in the PE file. Such an entry can be added manually in any PE editor. 

Alternativly, one can generate a `.lib` file from the DLL exports and link 
them together with the harness to create an entry in the `Import Directory`. 
Use `dumpbin /exports <filename>.dll` to extract the exports and paste the 
exported function names into a `.def` file. Use `lib /def:<deffile> /OUT:<libfile>`
to generate a `.lib` and add the library to the linker options. Once the usage of 
an export is detected (`__declspec(dllimport)`), the
linker adds the early DLL load.