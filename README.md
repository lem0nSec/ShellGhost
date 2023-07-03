# ShellGhost 👻

__A memory-based evasion technique for droppers which makes shellcode invisible from process start to end.__

-----------------------------------------------------------------------------------------------------------------------------------------------------------------
## Motivation
I came up with ShellGhost after a Metasploit shellcode inside one of my droppers was flagged as malicious by an EDR solution. The EDR correctly detected the shellcode placed into the .text segment after decryption. That's raised the need for having __a code that executes an 'invisible' shellcode__.


-----------------------------------------------------------------------------------------------------------------------------------------------------------------
## Handling the Thread Execution Flow
__ShellGhost relies on Vectored Exception Handling in combination with software breakpoints__ to cyclically stop thread execution, replacing the executed breakpoint with a RC4-encrypted shellcode instruction, decrypting the instruction and resuming execution after restoring memory protection to RX. When the subsequent EXCEPTION_BREAKPOINT is catched, the exception handler replaces the previous shellcode instruction with a new breakpoint so that the allocation will never disclose the complete shellcode in an unencrypted state. This happens inside a private memory page which is initially marked as READ/WRITE.
Having a RW PRV allocation will not be considered as an 'Indicator of Compromise' by memory scanners such as PE-Sieve and Moneta. When the allocation becomes RX and the page is scanned, nothing but breakpoints will be found. This happens while the shellcode is actually under execution. The following picture shows that a reverse shell is running, but no IOC are found by Moneta (other than the binary being unsigned).


![](pictures/moneta_detection.png)


-----------------------------------------------------------------------------------------------------------------------------------------------------------------
## Shellcode Mapping
Shellcode Mapping is the core functionality of ShellGhost. This tactic enables the thread to intermittently execute instructions while never exposing the entire shellcode in memory. This is possible because the position of each single shellcode instruction that the thread executes corresponds to the position of a certain breakpoint inside the allocated memory page. ShellGhost resolves this position by calculating the Relative Virtual Address (RVA) from the thread RIP to the base address of the allocated memory page and adds it to the base address of the encrypted shellcode / encrypted instructions. The number of breakpoints that will be replaced is not always the same, but it varies depending on the number of opcodes that each instruction needs to be correctly generated and interpreted (QUOTA). So for example the instruction 'POP RBP' is equal to '5D', which means only one breakpoint will be replaced. By contrast, the instruction 'JMP RAX' requires opcodes 'FF E0', so two breakpoints will be replaced. For this reason I created the following C data structure.


```c
typedef struct CRYPT_BYTES_QUOTA {

	DWORD RVA;		// offset to encrypted instruction 
	DWORD quota;	// number of opcodes that generate the instruction

} CRYPT_BYTES_QUOTA, * PCRYPT_BYTES_QUOTA;
```

Breakpoints are not immediately replaced with their instruction counterparts. This is because instructions are RC4-encrypted and need to undergo a decryption routine before being executed. This is where the `DWORD quota` comes into play. ShellGhost relies on the now popular 'SystemFunction032' to perform RC4 decryption. Unlike XOR, RC4 is not a single-byte encryption scheme. This means that the shellcode cannot be encrypted and decrypted all at once. This is also another reason why each instruction is treated separately. After the breakpoints are replaced, the buffer length that SystemFunction032 needs will be equal to the 'instruction quota', which again represents the number of opcodes the specific instruction is composed of. So for example, consider the following snippet.


```c

CRYPT_BYTES_QUOTA instruction[200];
instruction[5].quota = 2

USTRING buf = { 0 }; 	// will contain the buffer to be decrypted and its length
USTRING key = { 0 }; 	// will contain the RC4 key and length

buf.Length = 2 			// buffer length, or length of the instruction to be decrypted

```

We know that shellcode instruction number 5 is composed of 2 opcodes, so a buffer length of 2 will be passed to SystemFunction032. This is important because trying to decrypt the entire shellcode with a single call to SystemFunction032 will corrupt the shellcode.

### How Shellcode Mapping is performed?
The shellcode needs to be mapped with `ShellGhost_mapping.py` before compilation. The script extracts each single instruction and treats it as a small and independent shellcode. Instructions are encrypted with the RC4 algorithm one by one and the output is printed in C format. The result can be hardcoded inside the C code. Below is an example of what an encrypted MSF shellcode for calc.exe looks like. 


![](pictures/shellcode_mapping_1.png)


This shellcode has 98 instructions, so 98 CRYPT_BYTES_QUOTA structs are declared. When the code executes, these structs have to be populated with the proper instructions RVAs and QUOTAs. The '-1' parameter instructs the mapping script to print out the piece of code that does this.


![](pictures/shellcode_mapping_2.png)








- Problem: Adjustment of winapi call parameters
- Differences and Similarities with other techniques (Shellcode Fluctuation)
	- rc4 with systemfunction032
	- no hooking
	- MSF payloads
- Downsides and Room for Improvement



