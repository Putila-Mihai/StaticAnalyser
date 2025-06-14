
This is a lightweight, automated tool designed for static analysis of **ELF binaries**.

---

## ✨ Features

This analyzer offers a comprehensive overview of ELF binary structure and content, including:

* **ELF Structure Analysis:** parsing of the ELF header, sections, and segments.
* **Symbol Extraction:** Identification and listing of function and data symbols(if ELF is not stripped)
* **String Extraction:** Discovery of embedded strings, often revealing network indicators, configuration data, or internal commands.
* **Function Analysis:** Basic Control Flow Graph (CFG) generation for individual functions, aiding in understanding their logical flow.

The tool is built to process ELF binaries only compiled for **ARM** and **MIPS** architectures.

**Docker:** Ensure Docker Desktop (for Windows/macOS) or Docker Engine (for Linux) is installed and running on your system.

The analyzer is designed to run within a Docker container to ensure a consistent, isolated, and reproducible analysis environment.
*This should be runned on a vm preferably*

### 1. Build the Docker Image

First, navigate to the root directory of your project where your `Dockerfile` is:

```bash
docker build -t mirai-elf-analyzer .
```

This command builds the Docker image and tags it as `mirai-elf-analyzer`.

### 2. Run

need to use **volume mounts (`-v`)** to make your local sample files accessible inside the container and to save the analysis results back to your host machine.

#### **Command-Line Options:**

* `-f`, `--file <path_to_file_in_container>`: Specify the path to a **single ELF file** for analysis.
* `-d`, `--directory <path_to_directory_in_container>`: Specify the path to a **directory containing multiple ELF files** for batch analysis.
* `-o`, `--output <path_to_output_directory_in_container>`: Specify the base directory where analysis reports and visualizations will be saved.

#### **Examples:**

**a) Analyze a Single ELF File:**

```bash
docker run \
  -v /home/user/my_samples:/app/input_data \
  mirai-elf-analyzer \
  -f /app/input_data/malware.elf \
  -o /app/output_data/single_file_results
```

```bash
docker run mirai-elf-analyzer --help
```
if help needed

##scripts

available scripts to download samples from malware bazaar, unpack elfs.

## 🚧 Limitations & Future Work

-The tool is very limited.It supports only ARM and MIPS arhitecture (there are multiple others like X86, PowerPC, etc)
-The string xor decryptor is based only on a set of popular keys for mirai variants and use only a single XOR operation.This is why it is faulty.
-The heuristic used are very basic - they can be improved by testing on real samples adn modify rules accordingly.
-*More data handling and contextualization of the extracted features*
-*Improve the graph vizualization, maybe use some web tools*
-More modules for extra Features extraction or analysis
