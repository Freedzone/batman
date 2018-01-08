# batman
Kernel module to bypass Windows handle protection mechanisms (obCallbacks). Tested on x64 XP, 7.
"BATMAN HAS NO LIMITS."

## How does it work?
This module accepts any handle instance from user space and changes its access mask inside kernel data structures to specified one. After that the calling program can do whatever it wants with target handle (process, file): write to it, read its memory, kill, delete etc. For communication protocol refer to `IoCtl.h`. `CORE_STRUCTS.h` contains undocumented kernel structures. `Batman.c,h` driver's source code.
