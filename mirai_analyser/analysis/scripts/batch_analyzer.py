#Gemini Generated 

import os
from report_generator import ReportGenerator
from elf_parser import ELFParser # 

INPUT_SAMPLES_DIR = "/home/admin/mirai_analyzer/analysis/samples/samples/normal"


BASE_OUTPUT_RESULTS_DIR = "/home/admin/mirai_analyser/output/batch_analysis_results"


def is_elf_file(file_path: str) -> bool:
    """Checks if a file appears to be an ELF binary by reading its magic bytes."""
    try:
        with open(file_path, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    except IOError:
        return False

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"[*] Starting Simple Batch Analysis for: {INPUT_SAMPLES_DIR}")
    print(f"[*] Outputting results to: {BASE_OUTPUT_RESULTS_DIR}")
    print(f"{'='*60}\n")

    os.makedirs(BASE_OUTPUT_RESULTS_DIR, exist_ok=True)

    processed_count = 0
    skipped_count = 0
    error_count = 0

    for item_name in os.listdir(INPUT_SAMPLES_DIR):
        file_path = os.path.join(INPUT_SAMPLES_DIR, item_name)

        if os.path.isdir(file_path):
            print(f"[-] Skipping directory: {item_name}")
            continue
        if not is_elf_file(file_path):
            print(f"[-] Skipping non-ELF file: {item_name}")
            skipped_count += 1
            continue

        print(f"\n--- Analyzing: {item_name} ---")

        binary_output_subdir_name = item_name.replace('.', '_').replace('/', '_').replace('\\', '_')
        current_sample_output_dir = os.path.join(BASE_OUTPUT_RESULTS_DIR, binary_output_subdir_name)
        
        text_report_target_dir = os.path.join(current_sample_output_dir, "text_reports")
        viz_target_dir = os.path.join(current_sample_output_dir, "visualizations")

        os.makedirs(text_report_target_dir, exist_ok=True)
        os.makedirs(viz_target_dir, exist_ok=True)

        try:
            report_gen = ReportGenerator(file_path)
            report_gen.generate_full_report(
                output_file=f"{binary_output_subdir_name}_analysis_report.txt",
                text_report_output_dir=text_report_target_dir,
                generate_visualizations=True, 
                viz_output_dir=viz_target_dir
                  )
            processed_count += 1
            print(f"[*] Analysis complete for {item_name}. Results saved to: {current_sample_output_dir}")
        except Exception as e:
            print(f"[ERROR] Failed to analyze {item_name}: {e}")
            error_count += 1

    print(f"\n{'='*60}")
    print(f"[*] Batch Analysis Finished.")
    print(f"[*] Processed: {processed_count} files")
    print(f"[*] Skipped: {skipped_count} files (non-ELF)")
    print(f"[*] Errors: {error_count} files")
    print(f"{'='*60}\n")
    print(f"To download reports, use scp from your local machine:")
    print(f"  scp -r admin@<VM_IP>:{BASE_OUTPUT_RESULTS_DIR} /path/to/local/download_folder/")
