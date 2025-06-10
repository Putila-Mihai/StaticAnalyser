from report_generator import ReportGenerator
import os

filePath = "/home/mehigh/Documents/licenta/mirai_analyser/analysis/samples/test_arm"
    
if not os.path.exists(filePath):
    print(f"Error: Test binary not found at {filePath}")
    print("Please update 'filePath' variable to a valid ELF file path.")
else:
    report_output_file = f"{os.path.basename(filePath)}_analysis_report.txt"
    viz_output_base_dir = "mirai_analyser/output/malware_viz_out" # Top-level dir for all binary viz
    analysis_report_path = "/home/mehigh/Documents/licenta/mirai_analyser/output/analysis_reports"
    report_gen = ReportGenerator(filePath)
    report_gen.generate_full_report(
        output_file=report_output_file,
        text_report_output_dir=analysis_report_path,
        generate_visualizations=True,  # Set to False if you don't want graphs
        viz_output_dir=viz_output_base_dir
    )