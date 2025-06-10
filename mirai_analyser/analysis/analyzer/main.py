from elf_parser import ELFParser
from symbol_analyser import SymbolAnalyzer
from string_analyzer import StringAnalyzer
from CodeAnalyzer import CodeAnalyzer
import os

filePath = "/home/mehigh/Documents/licenta/mirai_analyser/samples/test_arm"
parser = ELFParser(filePath)
elf_info = parser.parse()

if elf_info: 
    symbol_analyzer = SymbolAnalyzer(elf_info)

    symbol_analyzer.analyze_symbols() 
    symbol_analyzer.display_analysis_result() 

    # string_analyzer = StringAnalyzer(elf_info)
    # string_analyzer.analyze_strings()
    # string_analyzer.print_report()
    
    code_analyzer = CodeAnalyzer(elf_info)
    code_analyzer.disassemble_code()
    code_analyzer.find_functions(symbol_analyzer.function_map)
    code_analyzer.build_control_flow_graphs()
    code_analyzer.print_analysis_summary()

    # Visualize the overall Call Graph
    call_graph_image_path = code_analyzer.visualize_call_graph(output_filename=f"{os.path.basename(filePath)}_call_graph")

    # Visualize a specific function's CFG (e.g., the ELF Entry Point)
    if elf_info.entry_point and elf_info.entry_point in code_analyzer.functions:
        entry_func_addr = elf_info.entry_point
        # Adjust entry point for Thumb mode if applicable (Capstone expects even addresses)
        if elf_info.machine_arch == 'ARM' and (entry_func_addr % 2 != 0):
             entry_func_addr -= 1 

        if entry_func_addr in code_analyzer.functions:
            code_analyzer.visualize_cfg(
                entry_func_addr,
                output_filename=f"{os.path.basename(filePath)}_{code_analyzer.functions[entry_func_addr].name}_cfg"
            )
        else:
            print(f"Could not visualize CFG for entry point 0x{elf_info.entry_point:x} as it's not a recognized function address.")
    else:
        print("No ELF Entry Point to visualize CFG for.")

    parser.close()
else:
    print("Error: Could not parse the ELF file. Please check the path and file permissions.")