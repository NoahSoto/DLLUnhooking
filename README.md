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

![](attachments/Pasted%20image%2020240615200831.png)



Then lets take a look at our memory map,

![](attachments/Pasted%20image%2020240615200911.png)

You can see where I've highlighted NTDLL.DLL.  This is where we're going to find systemcalls for Windows!  This library is stored in in `C:\Windows\System32\ntdll.dll`, alongside a plethora of other libraries for use by windows executables across the OS to quickly access these functions without having to redefine them over and over and over again.  More on that, and how that plays into memory addresses in a sec, but lets find a systemcall.

If you double click on the NTDLL.DLL line it will take you to the base address of the library and you can see that your CPU pane will display assmebly instructions at the address, and the dump pane provides a more wholistic overview of the region.  You can also see that they're viewing the same memory address, its super easy to get the addresses of the different panes confused which in turn messes you up so just double check :)

![](attachments/Pasted%20image%2020240615201226.png)


To get some more familiarity with other useful tools lets also run our executable and try using `Listdlls.exe` from sysinternals.  This program will list the used DLL's of another process.  We could also code something like this ourselves in C, and you'll see an implenentation of that in the DLL Unhooking code, that will examine the processes `Process Environment Block (PEB)` and parse through the `Ldr`, or loader data, for a list.  The PEB probably deserves a page of its own!

https://mohamed-fakroud.gitbook.io/red-teamings-dojo/windows-internals/peb
- Note the discussion of PEB LDR Data to see what I'm referring to.

Lets take a look at the binaries DLL's now.

![](attachments/Pasted%20image%2020240615213602.png)

```pwsh
.\Listdlls.exe StuffNthings.exe
```

Now I tried something for testing purposes in this screenshot.  The top image is with our code exactly as shown above, where we manually `LoadLibraryA` to bring `ntdll.dll` into the memory space of our `StuffNThings.exe` process.  The bottom one is without that `LoadLibraryA` call, so we can see that `ntdll.dll` appears to load into pretty much every process regardless of whether or not its explicity specified, or used in the actual runtime of the process.  Just something to note!

So with that being said, we can try and use this to find the .text section of the DLL.

Lets go back into x64 debugger and go to the .text section.  Then you can slowly and carefully scroll down and eventually you'll find the systemcall definitions!

![](attachments/Pasted%20image%2020240616001510.png)

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
The SSN is used to denote which systemcall is being ran.  These numbers change based on the Major and Minor version of Windows that you're using and increase sequentially through the library.  In this example 0 is `ZwAccessCheck`, 1 is `ZwWorkerFactoryReady` ,and so on.  `Nt` systemcalls are used to denote userland systemcalls while `Zw` is used to denote kernel mode systemcalls.  The functionality is nearly the same the only real difference is that in `Nt` systemcalls, since they come from userland, input parameters are treated as `untrusted`, and thus tested and validated prior to use.  That does not happen for `Zw` based systemcalls and they are kernel based and typically originate from things like drivers.

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

## DLL Unhooking!

These `jmp` instructions aren't overwritten into a processes memory address space until after the program is ready to begin executing, so we if start a new process but suspended, we can use this processes NTDLL as a clean unhooked copy, and then move it into our own local processes memory address space so that we can avoid all of those userland API hooks, or those `jmp` instructions!

All in all its another tool that we can add to our tool box.  In the `syscalls_work` repo we go over indirect systemcalls which are another way of avoiding the EDR inserted userland API hooks because we're writing the assembly, controlling the registers, and ultimately making systemcalls, all by ourselves. The part that really got me when implementing this was discerning whether or not the address of NTDLL in the local process, or the remote suspended process would change.  And what I found is that they're going typically going to be the same, which makes our job a lot easier since we need to have the address of both in order to copy our clean unhooked DLL from the suspended process into our hooked local process. Windows DLL's have a "preferred" or "recommended" base address offsets, the actual address will vary due to ASLR, and an order in which they're assigned memory locations on boot.  NTDLL and Kernel32.dll seem to be amongst the first ones allocated memory addresses so they'll likely get their preferred locations.

So essentially what we need to do is:
1. Find the local .text location
2. Find the local .text size
3. Create a suspended process
4. Check the .text of the remote suspended process using the local .text location since we know that the base address of the DLL, especailly for NTDLL, should be the same.
5. Copy the remote contents of the unhooked .text section from the remote process into a local memory buffer in our malicious process.
6. Change the memory protections of the local .text section to allow us to overwrite it
7. Copy our local unhooked DLL .text section into the actual module .text section.
8. Change the memory protections to reflect what they were prior to step 6
9. Make systemcalls as necessary to run shellcode, but now we're avoiding API hooks! 

There are pros and cons to both methods. Just in my own experience I think conceptually speaking indirect and direct systemcalls were actually a little bit easier for me to understand, but took a lot longer to implement.  The reason why I'm writing all of this is actually because it was so confusing to me at first that I really felt like I needed to do something more to solidify my understanding. I think DLL Unhooking is easier, but as mentioned in steps 6 and 8, I think needing the change the protection of NTDLL .text section is defintely pretty telling that a process could be malicious, and would be easier to detect then a non-direct systemcall implementation.  


## Resources:
I cannot thank these resources enough for providing me with inspiration and interest in these topics.  Additionally, they have provided fantastic assistance when I find myself stuck! 
MALDEV ACADEMY
https://unprotect.it/technique/dll-unhooking/
https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
