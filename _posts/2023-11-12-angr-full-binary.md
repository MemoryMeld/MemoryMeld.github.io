---
title: "Angr Overflow Analysis"
layout: "post"
categories: "Linux"
tags: ["Vulnerability Research", "Symbolic Execution", "Reverse Engineering"]
---

Hello everyone, 

I wanted to share my recent experience using Angr to detect overflows in binaries. I've dedicated several late nights to crafting an Angr script capable of identifying these overflows and now I'm eager to share my findings. My quest has been to explore alternative methods for analyzing binaries for memory corruption. From my experience, automated static analyzers have proven unreliable in detecting memory corruption.\
\
Even when armed with the source code, I strongly advocate for the utilization of coverage-guided fuzzing tools such as AFL++ or libFuzzer to unearth vulnerabilities, favoring them over static analyzers. My approach primarily involves employing AFL++ in qemu mode for testing binaries. However, complexities arise when handling binaries that rely on socket communication over networks. AFL++, primarily designed for file-based fuzzing, requires a workaround involving desock and binary patching to interact with binaries using sockets. A notable demonstration of this technique can be found in Attify's insightful blog, showcasing the process at [https://web.archive.org/web/20230819131007/https://blog.attify.com/fuzzing-iot-binaries-with-afl-part-ii/](https://web.archive.org/web/20230819131007/https://blog.attify.com/fuzzing-iot-binaries-with-afl-part-ii/).
\
In certain intricate scenarios, maneuvering through the complexities of patching binaries can be a daunting task. In these instances, I believe Angr becomes a valuable ally for researchers. I intend to delve into a specific recurrent case, delving into the insights gained while utilizing Angr to detect overflows. For this exploration, I'll be referencing code from the following GitHub repository: [https://github.com/shenfeng/tiny-web-server/tree/master](https://github.com/shenfeng/tiny-web-server/tree/master). This code harbors a known buffer overflow, manifesting at line 255 within the url\_decode function. My focus, however, won't revolve around the discovery and exploitation of this overflow, as these aspects have been extensively covered. Instead, I aim to scrutinize prevalent solutions to discern if they effectively detect this overflow.

\
The initial method I'll employ is detailed in this article: [https://security.humanativaspa.it/automating-binary-vulnerability-discovery-with-ghidra-and-semgrep/](https://security.humanativaspa.it/automating-binary-vulnerability-discovery-with-ghidra-and-semgrep/). The approach outlined in this article involves crafting semgrep rules and analyzing Ghidra's decompilation against those rules. However, this method is contingent on the presence of the memcpy function call in the decompilation. Notably, it's a common optimization by compilers to eliminate certain C library calls, including memcpy. In the context of the url\_decode function, the memcpy call is optimized out in both IDA and Ghidra's decompilation. Consequently, the absence of this call causes the semgrep rules to overlook the vulnerable section of code.


![](/assets/posts/2023-11-12-angr-full-binary/ida_decompilation_tiny.bmp)

![](/assets/posts/2023-11-12-angr-full-binary/ghidra_decompilation_tiny.bmp)

Another technique worth discussing involves utilizing cwe\_checker ([https://github.com/fkie-cad/cwe_checker](https://github.com/fkie-cad/cwe_checker)) to identify the vulnerability. However, upon executing cwe\_checker, it does not flag any vulnerability within the url\_decode function.

![](/assets/posts/2023-11-12-angr-full-binary/cwe_checker_tiny.bmp)

Now, I'll delve into my use of Angr to uncover the overflow within the url\_decode function. Despite its effectiveness, leveraging Angr for the analysis of extensive binaries has presented challenges, notably due to path explosion. Symbolic execution, a core aspect of Angr, systematically explores all potential execution paths within a program. However, in the case of large binaries characterized by numerous conditional branches, loops, and intricate control flow, the sheer volume of potential paths can multiply rapidly, leading to what's known as path explosion. This phenomenon significantly slows down the analysis process and often results in freezing my virtual machine.\
\
I highly recommend conducting Angr analyses on a VM or host equipped with ample CPU and memory resources to support the demanding nature of this process. In light of path explosion, I've often found greater success by directing Angr to a specific function address, initiating the analysis from that point onward. A great demonstration of this approach, focusing on pinpointing buffer overflows, is detailed in this gitbook: [https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/buffer-overflows](https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/buffer-overflows).\
\
I embarked on the challenge of analyzing the full binary to uncover the memcpy buffer overflow. Through numerous hours dedicated to debugging, making necessary modifications, and enduring VM freezes, I ultimately achieved this task. My initial approach involved extracting all functions from the binary's .text section, constructing a dictionary that Angr could reference during analysis. I specifically aimed to exclude any C library calls and functions attributed to the GCC toolchain. My objective was to obtain the start addresses for each instance the function was called, subsequently utilizing these addresses in Angr for overflow analysis. To accomplish this, I opted to employ radare2 for disassembling the binary due to its command-line interface and user-friendly nature. Below, I've included the code used for this stage.

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

The script's output highlights 22 cross-references, with just one pointing to url\_decode. The subsequent phase involves integrating this script logic into my Angr analysis. Enclosed below is the fully implemented script designed to retrieve all call start addresses and conduct buffer overflow analysis on each. To manage the load and mitigate potential VM freezes, I constrained the concurrent processes to 8. The analysis time per process was also limited to 5 seconds, a deliberate measure to address path explosion challenges. Although extending the analysis time could enhance path exploration, in this context, a shallow path traversal sufficed to pinpoint the overflow.

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

Reflecting on the test, it's evident that Angr showcases significant prowess in analyzing entire binaries to unveil shallow bugs. Moreover, when tasked with specific functions, Angr demonstrates exceptional capabilities. While the payload generation may not be immediately relevant, the ability to identify and isolate sections of code proves invaluable, enabling researchers to efficiently prioritize their reverse engineering efforts.
