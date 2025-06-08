from elf_parser import ELFParser
from symbol_analyser import SymbolAnalyzer
from string_analyzer import StringAnalyzer

parser = ELFParser("/home/mehigh/Documents/licenta/mirai_analyser/samples/xor_test")
elf_info = parser.parse()

if elf_info: 
    # symbol_analyzer = SymbolAnalyzer(elf_info)

    # symbol_analyzer.analyze_symbols() 
    # symbol_analyzer.display_analysis_result() 

    string_analyzer = StringAnalyzer(elf_info)
    string_analyzer.analyze_strings()
    string_analyzer.print_report()
    parser.close()
else:
    print("Error: Could not parse the ELF file. Please check the path and file permissions.")