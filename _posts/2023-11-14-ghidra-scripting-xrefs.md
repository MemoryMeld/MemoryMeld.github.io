# Ghidra Scripting - XRefs and Decompilation

Hello everyone, I'm excited to share the recent experiments I've been conducting with Ghidra scripting. The capabilities of Ghidra's decompiler and scripting tools truly stand out, surpassing what other disassemblers offer. Ghidra's headless mode particularly empowers researchers, granting the ability to extract essential information from binaries via the command line. The process of individually adding each binary to an active Ghidra project and running separate analyses can be tedious and time-consuming.

There have been numerous instances where I've needed to swiftly extract firmware and analyze multiple binaries to uncover cross-references related to specific C library function calls. This, in my view, is an area where Ghidra scripting excels. To initiate this process, the first step involves the installation of Ghidra 10.3.3 and running the software.

```bash
sudo apt install openjdk-17-jdk

wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.3_build/ghidra_10.3.3_PUBLIC_20230829.zip

unzip ghidra_10.3.3_PUBLIC_20230829.zip

ghidra_10.3.3_PUBLIC/./ghidraRun
```

Following this, the recommended next step is to establish a 'ghidra\_scripts' folder within your user's home directory or any preferred location. Subsequently, I suggest creating a Ghidra project dedicated to a specific binary. Once done, add your directory by navigating to Window -> Bundle Manager.


![](assets/posts/2023-11-12-ghidra-scripting-xrefs/bundle_manager.bmp)


Once our Ghidra scripts path is integrated into the Bundle Manager, the next step involves closing the current project and delving into code creation. A valuable example showcasing the utilization of Ghidra's headless mode for automated binary analysis can be found in this GitHub repository: [https://github.com/h4sh5/ghidra-headless-decompile/tree/master](https://github.com/h4sh5/ghidra-headless-decompile/tree/master). To enable the simultaneous analysis of multiple binaries, I established a dedicated 'binaries' folder, housing each separate binary for analysis. I maintain the Ghidra projects post-analysis, ensuring their availability for further examination if needed. Enclosed is the source code for my initial 'headless\_analyzer.py' script, designed to execute Ghidra's 'analyzeHeadless' shell script for each binary and subsequently run the 'analyzer.py' script to dump decompilation results.

```py
#!/usr/bin/env python3
import os
import subprocess
import time
import re

GHIDRA_PATH = os.path.expanduser("~/ghidra_10.3.3_PUBLIC")
GHIDRA_SCRIPT_PATH = os.path.expanduser("~/ghidra_scripts")
CURRENT_DIR = os.getcwd()

print("---------------------Started Analyzing------------------------")
print("")

start_time = time.time()

binaries_path = os.path.join(CURRENT_DIR, "binaries")
root_results_directory = os.path.join(CURRENT_DIR, "root_results")
os.makedirs(root_results_directory, exist_ok=True)
for fileName in os.listdir(binaries_path):
    binary_path = os.path.join(binaries_path, fileName)
    results_directory = os.path.join(root_results_directory, f"{fileName}_results")
    os.makedirs(results_directory, exist_ok=True)
    exported_source = os.path.join(results_directory, f"{fileName}_exported_source.c")

    # Run Ghidra Headless
    ghidra_project_name = f"{fileName}_ghidra_project"
    subprocess.run([
        f"{GHIDRA_PATH}/support/analyzeHeadless",
        results_directory,
        ghidra_project_name,
        "-import",
        binary_path,
        "-scriptPath",
        GHIDRA_SCRIPT_PATH,
        "-postscript",
        "analyzer.py",
        exported_source
    ])

end_time = time.time()
elapsed_time = round(end_time - start_time)

print("")
print("---------------------Finished Analyzing------------------------")
print(f"Elapsed time: {elapsed_time} seconds")
```

Subsequently, I've developed the preliminary code for my 'analyzer.py' script, leveraging Ghidra's embedded CppExporter functionality to retrieve the decompilation results.

```py
#!/usr/bin/env python2

#@author ReconDeveloper
#@category 
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.framework.plugintool.util import OptionsService
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import * 
from ghidra.program.model.address import *
from ghidra.app.util import Option
from ghidra.util.task import TaskMonitor
from java.io import File
from ghidra.app.util.exporter import CppExporter
from re import search

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
import __main__ as ghidra_app


def run():

    # getScriptArgs gets argument for this python script using `analyzeHeadless`
    args = ghidra_app.getScriptArgs()
        
    exporter = CppExporter()
    options = [Option(CppExporter.CREATE_HEADER_FILE, False)]
    exporter.setOptions(options)
    exporter.setExporterServiceProvider(state.getTool())
    print(args[0])

    f = File(args[0])
    exporter.export(f, ghidra_app.currentProgram, None, TaskMonitor.DUMMY)


if __name__ == '__main__':
    run()
```


![](assets/posts/2023-11-12-ghidra-scripting-xrefs/ghidra_script_initial.bmp)


The output from executing the 'headless\_analyzer.py' script is now visible, revealing the decompiled results for all three binaries alongside their corresponding Ghidra projects. While the exported source is comprehensive, encompassing not just '.text' code but also ELF header information and thunk functions, there's room for improvement. To refine the results, excluding dead code, thunk functions, and external symbols from the analysis could enhance the quality of the output. Below, I've included updated code for 'headless\_analyzer.py' to integrate a 'cleaned source' functionality.

```py
#!/usr/bin/env python3
import os
import subprocess
import time
import re

GHIDRA_PATH = os.path.expanduser("~/ghidra_10.3.3_PUBLIC")
GHIDRA_SCRIPT_PATH = os.path.expanduser("~/ghidra_scripts")
CURRENT_DIR = os.getcwd()

print("---------------------Started Analyzing------------------------")
print("")

start_time = time.time()

binaries_path = os.path.join(CURRENT_DIR, "binaries")
root_results_directory = os.path.join(CURRENT_DIR, "root_results")
os.makedirs(root_results_directory, exist_ok=True)
for fileName in os.listdir(binaries_path):
    binary_path = os.path.join(binaries_path, fileName)
    results_directory = os.path.join(root_results_directory, f"{fileName}_results")
    os.makedirs(results_directory, exist_ok=True)
    cleaned_source = os.path.join(results_directory, f"{fileName}_cleaned_source.c")
    exported_source = os.path.join(results_directory, f"{fileName}_exported_source.c")

    # Run Ghidra Headless
    ghidra_project_name = f"{fileName}_ghidra_project"
    subprocess.run([
        f"{GHIDRA_PATH}/support/analyzeHeadless",
        results_directory,
        ghidra_project_name,
        "-import",
        binary_path,
        "-scriptPath",
        GHIDRA_SCRIPT_PATH,
        "-postscript",
        "analyzer.py",
        cleaned_source,
        exported_source
    ])

end_time = time.time()
elapsed_time = round(end_time - start_time)

print("")
print("---------------------Finished Analyzing------------------------")
print(f"Elapsed time: {elapsed_time} seconds")
```

I've successfully implemented the functionality to print decompilation while excluding external symbols, dead code, and thunk functions. This enhancement took considerable effort, involving extensive research across multiple articles with similar objectives and cross-referencing against the Ghidra API.

```py
#!/usr/bin/env python2

#@author ReconDeveloper
#@category 
#@keybinding 
#@menupath 
#@toolbar 
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.framework.plugintool.util import OptionsService
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import * 
from ghidra.program.model.address import *
from ghidra.app.util import Option
from ghidra.util.task import TaskMonitor
from java.io import File
from ghidra.app.util.exporter import CppExporter

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
import __main__ as ghidra_app


class Analyzer:

    def __init__(self, program=None, timeout=None):

        # Initialize decompiler with current program
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(program or ghidra_app.currentProgram)
        self._options = DecompileOptions()
        self._tool = state.getTool()
        self._timeout = timeout


    def set_up_decompiler(self):
        if self._tool is not None:
            options_service = self._tool.getService(OptionsService)
            if options_service is not None:
                tool_options = options_service.getOptions("Decompiler")
                self._options.grabFromToolAndProgram(None, tool_options, program)

        #eliminate dead code
        self._options.setEliminateUnreachable(True)
        self._decompiler.setOptions(self._options)

        self._decompiler.toggleCCode(True)
        self._decompiler.toggleSyntaxTree(True)
        self._decompiler.setSimplificationStyle("decompile")

        return self._decompiler

    def get_all_functions(self):
        st = ghidra_app.currentProgram.getSymbolTable()
        si = st.getSymbolIterator()
        symbol_dict = {}
        funcs = []
        while si.hasNext():
            s = si.next()
            if ((s.getSymbolType() == SymbolType.FUNCTION) and (not s.isExternal())
                    and (not s.getName() in symbol_dict.keys())):
                symbol_dict[s.getName()] = s.getAddress()

        for address in symbol_dict.values():
            funcs.append(getFunctionAt(address))
        return funcs
           
    
    def decompile_func(self, func):
        # Decompile
        self._decompiler = self.set_up_decompiler()
        decomp_results = self._decompiler.decompileFunction(func, 0, self._timeout)
        if (decomp_results is not None) and (decomp_results.decompileCompleted()):
            return decomp_results.getDecompiledFunction().getC()
        return ""

    def decompile(self):
            
        pseudo_c = ''

        # Enumerate all functions and decompile each function
        funcs = self.get_all_functions()
        for func in funcs:
            if not func.isThunk():
                dec_func = self.decompile_func(func)
                if dec_func:
                    pseudo_c += dec_func

        return pseudo_c
   
def run():

    # getScriptArgs gets argument for this python script using `analyzeHeadless`
    args = ghidra_app.getScriptArgs()

    analyzer = Analyzer()
    decompiled_source_file = args[0]
    # Do decompilation process
    pseudo_c = analyzer.decompile()

    # Save to output file
    with open(decompiled_source_file, 'w') as fw:
        fw.write(pseudo_c)
        print('[*] saving decompilation to -> {}'.format(decompiled_source_file))
    
    exporter = CppExporter()
    options = [Option(CppExporter.CREATE_HEADER_FILE, False)]
    exporter.setOptions(options)
    exporter.setExporterServiceProvider(analyzer._tool)
    f = File(args[1])
    exporter.export(f, ghidra_app.currentProgram, None, TaskMonitor.DUMMY)


if __name__ == '__main__':
    run()
```


![](assets/posts/2023-11-12-ghidra-scripting-xrefs/ghidra_pretty.bmp)


Upon executing the 'headless\_analyzer.py' script, we now have refined source files for all of the binaries. This marks the culmination of the article and fulfills the main objective outlined at the beginning - obtaining cross-references to specific C library function calls. Below, I've included the final versions of the 'headless\_analyzer.py' and 'analyzer.py' scripts essential for achieving this specific task.

```py
#!/usr/bin/env python3
import os
import subprocess
import time
import re

GHIDRA_PATH = os.path.expanduser("~/ghidra_10.3.3_PUBLIC")
GHIDRA_SCRIPT_PATH = os.path.expanduser("~/ghidra_scripts")
CURRENT_DIR = os.getcwd()

print("---------------------Started Analyzing------------------------")
print("")

start_time = time.time()

binaries_path = os.path.join(CURRENT_DIR, "binaries")
root_results_directory = os.path.join(CURRENT_DIR, "root_results")
os.makedirs(root_results_directory, exist_ok=True)
for fileName in os.listdir(binaries_path):
    binary_path = os.path.join(binaries_path, fileName)
    results_directory = os.path.join(root_results_directory, f"{fileName}_results")
    os.makedirs(results_directory, exist_ok=True)
    result_xrefs = os.path.join(results_directory, f"{fileName}_xrefs.txt")
    cleaned_source = os.path.join(results_directory, f"{fileName}_cleaned_source.c")
    exported_source = os.path.join(results_directory, f"{fileName}_exported_source.c")

    # Run Ghidra Headless
    ghidra_project_name = f"{fileName}_ghidra_project"
    subprocess.run([
        f"{GHIDRA_PATH}/support/analyzeHeadless",
        results_directory,
        ghidra_project_name,
        "-import",
        binary_path,
        "-scriptPath",
        GHIDRA_SCRIPT_PATH,
        "-postscript",
        "analyzer.py",
        result_xrefs,
        cleaned_source,
        exported_source
    ])

end_time = time.time()
elapsed_time = round(end_time - start_time)

print("")
print("---------------------Finished Analyzing------------------------")
print(f"Elapsed time: {elapsed_time} seconds")
```



```py
#!/usr/bin/env python2

#@author ReconDeveloper
#@category 
#@keybinding 
#@menupath 
#@toolbar 
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.framework.plugintool.util import OptionsService
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import * 
from ghidra.program.model.address import *
from ghidra.app.util import Option
from ghidra.util.task import TaskMonitor
from java.io import File
from ghidra.app.util.exporter import CppExporter
from re import search

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
import __main__ as ghidra_app


class Analyzer:

    def __init__(self, program=None, timeout=None):

        # Initialize decompiler with current program
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(program or ghidra_app.currentProgram)
        self._options = DecompileOptions()
        self._tool = state.getTool()
        self._timeout = timeout


    def set_up_decompiler(self):
        if self._tool is not None:
            options_service = self._tool.getService(OptionsService)
            if options_service is not None:
                tool_options = options_service.getOptions("Decompiler")
                self._options.grabFromToolAndProgram(None, tool_options, program)

        # eliminate dead code
        self._options.setEliminateUnreachable(True)
        self._decompiler.setOptions(self._options)

        self._decompiler.toggleCCode(True)
        self._decompiler.toggleSyntaxTree(True)
        self._decompiler.setSimplificationStyle("decompile")

        return self._decompiler

    def get_all_functions(self):
        st = ghidra_app.currentProgram.getSymbolTable()
        si = st.getSymbolIterator()
        symbol_dict = {}
        funcs = []
        while si.hasNext():
            s = si.next()
            if ((s.getSymbolType() == SymbolType.FUNCTION) and (not s.isExternal())
                    and (not s.getName() in symbol_dict.keys())):
                symbol_dict[s.getName()] = s.getAddress()

        for address in symbol_dict.values():
            funcs.append(getFunctionAt(address))
        return funcs
           
    
    def decompile_func(self, func):
        # Decompile
        self._decompiler = self.set_up_decompiler()
        decomp_results = self._decompiler.decompileFunction(func, 0, self._timeout)
        if (decomp_results is not None) and (decomp_results.decompileCompleted()):
            return decomp_results.getDecompiledFunction().getC()
        return ""

    def decompile(self):
            
        pseudo_c = ''

        # Enumerate all functions and decompile each function
        funcs = self.get_all_functions()
        for func in funcs:
            if not func.isThunk():
                dec_func = self.decompile_func(func)
                if dec_func:
                    pseudo_c += dec_func

        return pseudo_c

    def list_cross_references(self, dst_func, tag, output_path):
        dst_name = dst_func.getName()
        dst_addr = dst_func.getEntryPoint()
        references = getReferencesTo(dst_addr) # limited to 4096 records
        xref_addresses = []
        f = open(output_path,'a')
        for xref in references:
            if xref.getReferenceType().isCall(): 
                call_addr = xref.getFromAddress()
                src_func = getFunctionContaining(call_addr)
                if src_func is not None:
                    xref_addresses.append(src_func.getEntryPoint())
                    if ((not src_func.isThunk()) and (xref_addresses.count(src_func.getEntryPoint()) < 2)):
                        results = str(self.decompile_func(src_func))
                        for line in results.splitlines():
                            if search(dst_name, line):
                                print >>f, "Call to {} in {} at {} has function signature of: {}" \
                                    .format(dst_name,src_func.getName(), \
                                        call_addr, line)
        f.close()

    def get_imported_functions(self, output_path):

        import_functions = [ 
            
            # No bounds checking, buffer overflows common
            "strcpy", "sprintf", "vsprintf", "strcat", "getpass",
            "strlen", #needs null terminator!

            # Windows specific functions, buffer overflows common
            "makepath", "_makepath", "_splitpath", "snscanf", "_snscanf",

            # Copy functions Windows API and kernel driver functions 
            "RtlCopyMemory", "CopyMemory",

            # When given %s specifier, can cause overflow, if scanf("%10s", buf) still check size of buffer to see if smaller
            "scanf", "fscanf", "sscanf", "__isoc99_scanf", "__isoc99_fscanf", "__isoc99_sscanf",

            # Often bounds is based on size of input
            "snprintf", "strncpy", "strncat",

            # Printf functions, check for format string 
            "printf", "fprintf",

            # Check for insecure use of environment variables
            "getenv",
            # Check if size arg can contain negative numbers or zero, return value must be checked
            "malloc",
            # Potential implicit overflow due to integer wrapping
            "calloc",
            # Doesn't initialize memory to zero; realloc(0) is equivalent to free
            "realloc",
            # check for incorrect use, double free, use after free
            "free", "_free",

            # I/O functions 
            "fgets", "fread", "fwrite", "read", "recv", "recvfrom", "write",

            # Check for command injection and shell exploitation (runs with shell on machine)
            "system",  "popen",

            # Check for command injection and 
            # File descriptor handling, might inherit open file descriptors from calling process
            # If sensitive file descriptors are left open or not handled correctly, it can lead to information leak  
            "execl", "execlp", "execle", "execv", "execve", "execvp", "execvpe",

            # Common static memory copy functions in libc
            "memcpy", "memset", "bcopy"]
         

        tag = "Imported Function"
        st = ghidra_app.currentProgram.getSymbolTable()
        si = st.getSymbolIterator()
        symbol_dict = {}
        funcs = []
        while si.hasNext():
            s = si.next()
            if ((s.getSymbolType() == SymbolType.FUNCTION) and (not s.isExternal())
                    and (s.getName() in import_functions) and (not s.getName() in symbol_dict.keys())):
                symbol_dict[s.getName()] = s.getAddress()

        for address in symbol_dict.values():
            funcs.append(getFunctionAt(address))

        for f in funcs:
           self.list_cross_references(f,tag,output_path)      


def run():

    # getScriptArgs gets argument for this python script using `analyzeHeadless`
    args = ghidra_app.getScriptArgs()
    
    f = open(args[0],'w')
    print >>f, 'Xref Results \n-----------------------------\n'
    f.close()

    analyzer = Analyzer()
    analyzer.get_imported_functions(args[0])
    decompiled_source_file = args[1]

    # Perform selective decompilation process
    pseudo_c = analyzer.decompile()

    # Save to output file
    with open(decompiled_source_file, 'w') as fw:
        fw.write(pseudo_c)
        print('[*] saving decompilation to -> {}'.format(decompiled_source_file))
    
    exporter = CppExporter()
    options = [Option(CppExporter.CREATE_HEADER_FILE, False)]
    exporter.setOptions(options)
    exporter.setExporterServiceProvider(analyzer._tool)
    f = File(args[2])
    exporter.export(f, ghidra_app.currentProgram, None, TaskMonitor.DUMMY)


if __name__ == '__main__':
    run()
```


![](assets/posts/2023-11-12-ghidra-scripting-xrefs/ghidra_xrefs.bmp)


The output from running 'headless\_analyzer.py' now incorporates an 'xrefs.txt' file, cataloging the cross-references for all the analyzed binaries. This ability to obtain cross-references to C library function calls across multiple binaries through headless scripting is an incredibly powerful feature. That is all for this blog post, I appreciate everyone taking the time to read it!