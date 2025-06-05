from elf_parser import ELFParser
from symbol_analyser import SymbolAnalyzer

parser = ELFParser("/home/mehigh/Documents/licenta/mirai_analyser/samples/big_file_stripped.elf")
elf_info = parser.parse()

if elf_info: 
    symbol_analyzer = SymbolAnalyzer(elf_info)

    symbol_analyzer.analyze_symbols() 
    symbol_analyzer.display_analysis_result() 
    parser.close()
else:
    print("Error: Could not parse the ELF file. Please check the path and file permissions.")