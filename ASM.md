Assembly program can be divided into three sections :
- The **data** section
	- The **data** section is used for declaring initialized data or constants. This data does not change at runtime. You can declare various constant values, file names, or buffer size, etc., in this section.
- The **bss** section
	- The **bss** section is used for declaring variables.
- The **text** section
	- The **text** section is used for keeping the actual code. This section must begin with the declaration **global _start**, which tells the kernel where the program execution begins.

Assembly language programs consist of three types of statements :
- Executable instructions or instructions
	- The **executable instructions** or simply **instructions** tell the processor what to do. Each instruction consists of an **operation code** (opcode). Each executable instruction generates one machine language instruction.
- Assembler directives or pseudo-ops
	- The **assembler directives** or **pseudo-ops** tell the assembler about the various aspects of the assembly process. These are non-executable and do not generate machine language instructions.
- Macros
	- **Macros** are basically a text substitution mechanism.

# Hello World program 

```  
section .text
	global _start ;must be declared for linker (ld) 

_start: ;tells linker entry point 
	mov edx,len ;message length 
	mov ecx,msg ;message to write 
	mov ebx,1 ;file descriptor (stdout) 
	mov eax,4 ;system call number (sys_write) 
	int 0x80 ;call kernel 

	mov eax,1 ;system call number (sys_exit) 
	int 0x80 ;call kernel 

section .data 
msg db 'Hello, world!', 0xa ;string to be printed 
len equ $ - msg ;length of the string
```


we can specify various memory segments as :

- **Data segment** 
	- It is represented by **.data** section and the **.bss**. The .data section is used to declare the memory region, where data elements are stored for the program. This section cannot be expanded after the data elements are declared, and it remains static throughout the program.
	- The .bss section is also a static memory section that contains buffers for data to be declared later in the program. This buffer memory is zero-filled.
- **Code segment** 
	- It is represented by **.text** section. This defines an area in memory that stores the instruction codes. This is also a fixed area.
- **Stack** 
	- This segment contains data values passed to functions and procedures within the program.


---

# Processor Registers 

The registers are grouped into three categories −

1. General registers
	- Data registers
	- Pointer registers
	- Index registers
2. Control registers
3. Segment registers.


## **General registers**

### Data Registers :
- our 32-bit data registers are used for arithmetic, logical, and other operations.
- As complete 32-bit data registers: EAX, EBX, ECX, EDX.
- **AX is the primary accumulator**; it is used in input/output and most arithmetic instructions.
- **BX is known as the base register**, as it could be used in indexed addressing.
- **CX is known as the count register**
- **DX is known as the data register**. It is also used in input/output operations.

### Pointer Registers :
- The pointer registers are 32-bit EIP, ESP, and EBP registers
- **Instruction Pointer (IP)** − The 16-bit IP register stores the offset address of the next instruction to be executed. IP in association with the CS register (as CS:IP) gives the complete address of the current instruction in the code segment.
- **Stack Pointer (SP)** − The 16-bit SP register provides the offset value within the program stack. SP in association with the SS register (SS:SP) refers to be current position of data or address within the program stack.
- **Base Pointer (BP)** − The 16-bit BP register mainly helps in referencing the parameter variables passed to a subroutine. The address in SS register is combined with the offset in BP to get the location of the parameter. BP can also be combined with DI and SI as base register for special addressing.

### Index Registers :
- The 32-bit index registers, ESI and EDI, and their 16-bit rightmost portions.
- used for indexed addressing and sometimes used in addition and subtraction.
- **Source Index (SI)** − It is used as source index for string operations.
- **Destination Index (DI)** − It is used as destination index for string operations.

## **Control registers**

The 32-bit instruction pointer register and the 32-bit flags register combined are considered as the control registers.

The common flag bits are :
- **Overflow Flag (OF)** − It indicates the overflow of a high-order bit (leftmost bit) of data after a signed arithmetic operation.
- **Direction Flag (DF)** − It determines left or right direction for moving or comparing string data. When the DF value is 0, the string operation takes left-to-right direction and when the value is set to 1, the string operation takes right-to-left direction.
- **Interrupt Flag (IF)** − It determines whether the external interrupts like keyboard entry, etc., are to be ignored or processed. It disables the external interrupt when the value is 0 and enables interrupts when set to 1.
- **Trap Flag (TF)** − It allows setting the operation of the processor in single-step mode. The DEBUG program we used sets the trap flag, so we could step through the execution one instruction at a time.
- **Sign Flag (SF)** − It shows the sign of the result of an arithmetic operation. This flag is set according to the sign of a data item following the arithmetic operation. The sign is indicated by the high-order of leftmost bit. A positive result clears the value of SF to 0 and negative result sets it to 1.
- **Zero Flag (ZF)** − It indicates the result of an arithmetic or comparison operation. A nonzero result clears the zero flag to 0, and a zero result sets it to 1.
- **Auxiliary Carry Flag (AF)** − It contains the carry from bit 3 to bit 4 following an arithmetic operation; used for specialized arithmetic. The AF is set when a 1-byte arithmetic operation causes a carry from bit 3 into bit 4.
- **Parity Flag (PF)** − It indicates the total number of 1-bits in the result obtained from an arithmetic operation. An even number of 1-bits clears the parity flag to 0 and an odd number of 1-bits sets the parity flag to 1.
- **Carry Flag (CF)** − It contains the carry of 0 or 1 from a high-order bit (leftmost) after an arithmetic operation. It also stores the contents of last bit of a _shift_ or _rotate_ operation.


The following table indicates the position of flag bits in the 16-bit Flags register :

| Flag:   |       | O   | D   | I   | T   | S   | Z   |     | A   |     | P   |     | C   |
| ------- | ----- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Bit no: | 15:12 | 11  | 10  | 9   | 8   | 7   | 6   | 5   | 4   | 3   | 2   | 1   | 0   |


## **Segment registers**

Segments are specific areas defined in a program for containing data, code and stack. There are three main segments
- **Code Segment** − It contains all the instructions to be executed. A 16-bit Code Segment register or CS register stores the starting address of the code segment.
- **Data Segment** − It contains data, constants and work areas. A 16-bit Data Segment register or DS register stores the starting address of the data segment.
- **Stack Segment** − It contains data and return addresses of procedures or subroutines. It is implemented as a 'stack' data structure. The Stack Segment register or SS register stores the starting address of the stack.

---
# System Calls

System calls are APIs for the interface between the user space and the kernel space. We have already used the system calls. sys_write and sys_exit, for writing into the screen and exiting from the program, respectively.

for using Linux system calls in your program :
- Put the system call number in the EAX register.
- Store the arguments to the system call in the registers EBX, ECX, etc.
- Call the relevant interrupt (80h).
- The result is usually returned in the EAX register.

There are six registers that store the arguments of the system call used. These are the EBX, ECX, EDX, ESI, EDI, and EBP. These registers take the consecutive arguments, starting with the EBX register. If there are more than six arguments, then the memory location of the first argument is stored in the EBX register.

The following code snippet shows the use of the system call sys_exit :

```
mov eax,1 ; system call number (sys_exit) 
int 0x80 ; call kernel
```

The following code snippet shows the use of the system call sys_write :

```
mov edx,4 ; message length 
mov ecx,msg ; message to write 
mov ebx,1 ; file descriptor (stdout) 
mov eax,4 ; system call number (sys_write) 
int 0x80 ; call kernel
```

The following example reads a number from the keyboard and displays it on the screen :

```
section .data                           ;Data segment
   userMsg db 'Please enter a number: ' ;Ask the user to enter a number
   lenUserMsg equ $-userMsg             ;The length of the message
   dispMsg db 'You have entered: '
   lenDispMsg equ $-dispMsg                 

section .bss           ;Uninitialized data
   num resb 5

section .text          ;Code Segment
   global _start

_start:                ;User prompt
   mov eax, 4
   mov ebx, 1
   mov ecx, userMsg
   mov edx, lenUserMsg
   int 80h

   ;Read and store the user input
   mov eax, 3
   mov ebx, 2
   mov ecx, num  
   mov edx, 5          ;5 bytes (numeric, 1 for sign) of that information
   int 80h

   ;Output the message 'The entered number is: '
   mov eax, 4
   mov ebx, 1
   mov ecx, dispMsg
   mov edx, lenDispMsg
   int 80h  

   ;Output the number entered
   mov eax, 4
   mov ebx, 1
   mov ecx, num
   mov edx, 5
   int 80h  
 
   ; Exit code
   mov eax, 1
   mov ebx, 0
   int 80h
```

---
# Addressing Modes

The modes of addressing are
- Register addressing
- Immediate addressing
- Direct Memory addressing
- Direct-Offset Addressing
- Indirect Memory Addressing

# Variables
- Each byte of character is stored as its ASCII value in hexadecimal.
- Each decimal value is automatically converted to its 16-bit binary equivalent and stored as a hexadecimal number.
- Processor uses the little-endian byte ordering.
- Negative numbers are converted to its 2's complement representation.
- Short and long floating-point numbers are represented using 32 or 64 bits, respectively.

## Multiple Definitions

```
choice DB 'Y'           ;ASCII of y = 79H 
number1 DW 12345        ;12345D = 3039H 
number2 DD 12345679     ;123456789D = 75BCD15H
```

## Multiple Initializations

```
marks  TIMES  9  DW  0
```


The **%assign** directive can be used to define numeric constants like the EQU directive. This directive allows redefinition.
The **%define** directive allows defining both numeric and string constants. This directive is similar to the \#define in C.


```
mov al,'3' 
sub al, '0'
```

Subtracting '0' from '3' in assembly language converts the ASCII character '3' to its corresponding integer value. ASCII for '3' is 51, and ASCII for '0' is 48. By performing the subtraction, you get 3, which is the integer representation of the character '3'.

---
## ASCII Representation

There are four instructions for processing numbers in ASCII representation
- **AAA** − ASCII Adjust After Addition
- **AAS** − ASCII Adjust After Subtraction
- **AAM** − ASCII Adjust After Multiplication
- **AAD** − ASCII Adjust Before Division

These instructions do not take any operands and assume the required operand to be in the AL register.

