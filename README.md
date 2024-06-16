## EDR Detection of API/Syscalls

One common method of detecting syscall usage by various EDR solutions is to "hook" the the functions.  

How does this work, what does that even mean?

Lets take a look at a basic windows syscall in assembly.


Lets spin up a project in VS quickly and just take a look at the libraries their addresses, syscall structure, ect.

![](attachments/Pasted%20image%2020240615213133.png)

```c
#include <windows.h>

int main() {
	HMODULE hNTDLL = LoadLibraryA("ntdll.dll");
	getchar();
}
```

Now if we build and run we can attach x64debugger to this process and we can begin to dive in!

Attach = Control + A

![](Pasted%20image%2020240615200831.png)



Then lets take a look at our memory map,

![](Pasted%20image%2020240615200911.png)

You can see where I've highlighted NTDLL.DLL.  This is where we're going to find systemcalls for Windows!  This library is stored in in `C:\Windows\System32\ntdll.dll`, alongside a plethora of other libraries for use by windows executables across the OS to quickly access these functions without having to redefine them over and over and over again.  More on that, and how that plays into memory addresses in a sec, but lets find a systemcall.

If you double click on the NTDLL.DLL line it will take you to the base address of the library and you can see that your CPU pane will display assmebly instructions at the address, and the dump pane provides a more wholistic overview of the region.  You can also see that they're viewing the same memory address, its super easy to get the addresses of the different panes confused which in turn messes you up so just double check :)

![](Pasted%20image%2020240615201226.png)


To get some more familiarity with other useful tools lets also run our executable and try using `Listdlls.exe` from sysinternals.  This program will list the used DLL's of another process.  We could also code something like this ourselves in C, and you'll see an implenentation of that in the DLL Unhooking code, that will examine the processes `Process Environment Block (PEB)` and parse through the `Ldr`, or loader data, for a list.  The PEB probably deserves a page of its own!

https://mohamed-fakroud.gitbook.io/red-teamings-dojo/windows-internals/peb
- Note the discussion of PEB LDR Data to see what I'm referring to.

Lets take a look at the binaries DLL's now.

![](Pasted%20image%2020240615213602.png)

```pwsh
.\Listdlls.exe StuffNthings.exe
```

Now I tried something for testing purposes in this screenshot.  The top image is with our code exactly as shown above, where we manually `LoadLibraryA` to bring `ntdll.dll` into the memory space of our `StuffNThings.exe` process.  The bottom one is without that `LoadLibraryA` call, so we can see that `ntdll.dll` appears to load into pretty much every process regardless of whether or not its explicity specified, or used in the actual runtime of the process.  Just something to note!

So with that being said, we can try and use this to find the .text section of the DLL.

Lets go back into x64 debugger and go to the .text section.  Then you can slowly and carefully scroll down and eventually you'll find the systemcall definitions!

![](Pasted%20image%2020240616001510.png)

They're denoted by the name of the systemcall in red on the right.

Note the general format:

```c
mov r10,rcx
mov eax,SSN
...
...
syscall
ret
```

So we can see the general structure of a system call repeated in all 3 instances here.

THis is an example of an unhooked systemcall.  In a hooked systemcall the structure will more closely resemble something like this:

```
jmp <edr_memory_space_for_analysis>
mov r10,rcx
mov eax,SSN
...
...
syscall
ret
```

How do we avoid this?

DLL Unhooking!

These `jmp` instructions aren't overwritten into a processes memory address space until after the program is ready to begin executing, so we if start a new process but suspended, we can use this processes NTDLL as a clean unhooked copy, and then move it into our own local processes memory address space so that we can avoid all of those userland API hooks, or those `jmp` instructions!


## Resources:
I cannot thank these resources enough for providing me with inspiration and interest in these topics.  Additionally, they have provided fantastic assistance when I find myself stuck! 
MALDEV ACADEMY
https://unprotect.it/technique/dll-unhooking/
https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
