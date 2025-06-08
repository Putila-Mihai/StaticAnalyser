from elf_parser import ELFParser
from symbol_analyser import SymbolAnalyzer
from string_analyzer import StringAnalyzer
from CodeAnalyzer import CodeAnalyzer

parser = ELFParser("/home/mehigh/Documents/licenta/mirai_analyser/samples/test_arm_stripped")
elf_info = parser.parse()

if elf_info: 
    symbol_analyzer = SymbolAnalyzer(elf_info)

    symbol_analyzer.analyze_symbols() 
    # symbol_analyzer.display_analysis_result() 

    # string_analyzer = StringAnalyzer(elf_info)
    # string_analyzer.analyze_strings()
    # string_analyzer.print_report()
    
    code_analyzer = CodeAnalyzer(elf_info)
    code_analyzer.disassemble_code()
    code_analyzer.find_functions(symbol_analyzer.function_map)
    print(code_analyzer.functions)
    
    parser.close()
else:
    print("Error: Could not parse the ELF file. Please check the path and file permissions.")