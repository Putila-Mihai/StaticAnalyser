import argparse
import os
import sys

from report_generator import ReportGenerator 
from elf_parser import ELFParser 

def is_elf_file(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    except IOError:
        return False
    except Exception as e:
        print(f"Error checking ELF magic bytes for {file_path}: {e}", file=sys.stderr)
        return False

def analyze_single_file_logic(file_path: str, base_output_results_dir: str):
    item_name = os.path.basename(file_path)
    print(f"\n--- Analyzing: {item_name} ---")

    binary_output_subdir_name = item_name.replace('.', '_').replace('/', '_').replace('\\', '_')
    current_sample_output_dir = os.path.join(base_output_results_dir, binary_output_subdir_name)
    
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
        print(f"[*] Analysis complete for {item_name}. Results saved to: {current_sample_output_dir}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to analyze {item_name}: {e}", file=sys.stderr)
        return False

def run_batch_analysis(input_samples_dir: str, base_output_results_dir: str):
    print(f"\n{'='*60}")
    print(f"[*] Starting Batch Analysis for: {input_samples_dir}")
    print(f"[*] Outputting results to: {base_output_results_dir}")
    print(f"{'='*60}\n")

    os.makedirs(base_output_results_dir, exist_ok=True)

    processed_count = 0
    skipped_count = 0
    error_count = 0

    for item_name in os.listdir(input_samples_dir):
        file_path = os.path.join(input_samples_dir, item_name)
        if os.path.isdir(file_path):
            print(f"[-] Skipping directory: {item_name}")
            continue
        if not is_elf_file(file_path):
            print(f"[-] Skipping non-ELF file: {item_name} (Not an ELF binary)")
            skipped_count += 1
            continue
        if analyze_single_file_logic(file_path, base_output_results_dir):
            processed_count += 1
        else:
            error_count += 1

    print(f"\n{'='*60}")
    print(f"[*] Batch Analysis Finished.")
    print(f"[*] Total files scanned: {processed_count + skipped_count + error_count}")
    print(f"[*] Successfully Processed: {processed_count} files")
    print(f"[*] Skipped: {skipped_count} files (non-ELF)")
    print(f"[*] Errors: {error_count} files")
    print(f"{'='*60}\n")
    print(f"To access reports, check the '{os.path.basename(base_output_results_dir)}' directory locally.")
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Static analysis framework for ELF malware.",
        formatter_class=argparse.RawTextHelpFormatter 
    )

    input_group = parser.add_mutually_exclusive_group(required=True)

    input_group.add_argument(
        '-f', '--file',
        type=str,
        help="Path to a single ELF file to analyze."
    )
    input_group.add_argument(
        '-d', '--directory',
        type=str,
        help="Path to a directory containing ELF files for batch analysis."
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='analysis_results',
        help="Path to the base output directory for results. Defaults to 'analysis_results'."
    )

    args = parser.parse_args()

    if not os.path.exists(args.output):
        try:
            os.makedirs(args.output)
            print(f"Created output directory: {args.output}")
        except OSError as e:
            print(f"Error creating output directory '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Using output directory: {args.output}")

    if args.file:
       
        input_path = args.file
        if not os.path.isfile(input_path):
            print(f"Error: Input file not found at '{input_path}'", file=sys.stderr)
            sys.exit(1)
        if not is_elf_file(input_path):
            print(f"Error: '{input_path}' is not an ELF binary.", file=sys.stderr)
            sys.exit(1)

        analyze_single_file_logic(input_path, args.output)

    elif args.directory:
        input_path = args.directory
        if not os.path.isdir(input_path):
            print(f"Error: Input directory not found at '{input_path}'", file=sys.stderr)
            sys.exit(1)
        
        run_batch_analysis(input_path, args.output)
    
    print("\nAll analysis tasks finished successfully." if not sys.stderr else "\nAnalysis finished with errors. Please check logs.")