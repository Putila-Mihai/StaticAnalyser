from elf_parser import ELFParser, ELFInfo
from symbol_analyzer import SymbolAnalyzer 
from code_analyzer import CodeAnalyzer
from string_analyzer import StringAnalyzer
from config import *
import os
from typing import Dict, Any, Optional

class ReportGenerator:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.elf_parser = ELFParser(file_path)
        self.elf_info = None
        self.symbol_analyzer = None
        self.code_analyzer = None
        self.string_analyzer = None 

    def generate_full_report(self, output_file: str = "malware_analysis_report.txt", 
                             generate_visualizations: bool = True,
                             text_report_output_dir: str = "analysis_reports",
                             viz_output_dir: str = "analysis_visualizations",
                             cfg_viz_options: Optional[Dict[str, Any]] = None) -> None:
        full_report_content = []
        generated_viz_files = []
        try:
            print(f"[*] Starting full analysis for: {self.file_path}")

            print("  - Running ELF Parser...")
            self.elf_info = self.elf_parser.parse()
            if self.elf_info:
                full_report_content.append(self.elf_parser.get_report())
            else:
                full_report_content.append("\n[ERROR] ELF Parsing failed. Cannot generate full report.\n")
                return

            print("  - Running Symbol Analyzer...")
            self.symbol_analyzer = SymbolAnalyzer(self.elf_info) 
            self.symbol_analyzer.analyze_symbols() 
            full_report_content.append(self.symbol_analyzer.get_report())
            
            print("  - Running String Analyzer...")
            self.string_analyzer = StringAnalyzer(self.elf_info) # Initialize StringAnalyzer
            self.string_analyzer.analyze_strings() # Run the analysis
            string_report_lines = self.string_analyzer.get_report()
            full_report_content.append("\n".join(string_report_lines))
            
            
            print("  - Running Code Analyzer (Disassembly, Functions, CFG, Call Graph)...")
            self.code_analyzer = CodeAnalyzer(self.elf_info)
            symbol_analysis_result = self.symbol_analyzer.get_analysis_result() 
            if self.code_analyzer.disassemble_code():
                self.code_analyzer.find_functions(symbol_analysis_result) 
                self.code_analyzer.build_control_flow_graphs()
                
                full_report_content.append(self.code_analyzer.get_report())

                if generate_visualizations:
                    binary_base_name = os.path.basename(self.file_path).replace('.', '_')
                    viz_files = self.code_analyzer.get_visualization(
                        output_dir=os.path.join(viz_output_dir, binary_base_name),
                        base_name=binary_base_name
                    )
                    generated_viz_files.extend(viz_files)

            else:
                full_report_content.append("\n[ERROR] Code Analysis failed (disassembly error).\n")
            report_path = os.path.join(text_report_output_dir,output_file)
           
            with open(report_path, 'w') as f:
                f.write("\n".join(full_report_content))
            
            print(f"[*] Full analysis report saved to: {output_file}")

            if generated_viz_files:
                with open(output_file, 'a') as f: # Append to existing report
                    f.write(f"\n\n--- Visualizations Generated ---\n")
                    f.write(f"Visualizations saved to: {os.path.join(viz_output_dir, binary_base_name)}\n")
                    f.write("Generated graph files:\n")
                    for viz_file in generated_viz_files:
                        f.write(f"- {viz_file}\n")


        except Exception as e:
            print(f"[CRITICAL ERROR] An error occurred during report generation: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.elf_parser.close()