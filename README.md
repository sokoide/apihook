# API Hook for Windows
## About
* install_hook.exe
console app to intall hook dll to a target process.

* sample_hook.dll
dll to be hooked into a process.

## How it works
### install_hook.exe
It injects a specified dll to a target process using CreateRemoteThread API.

### sample_hook.dll
When it's loaded, DllMain iterates all the loaded module and updates IAT for CreateWindowExW to detour the API.

EOF