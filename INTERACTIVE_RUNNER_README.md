# Interactive Launcher Guide

## 🚀 Introduction

`interactive_runner.py` is a user-friendly command-line interface for the CodeQL CWE Batch Processor. It simplifies the process of configuring and running the batch processing script by guiding you through a series of interactive prompts.

## ✨ Features

- **Interactive Selection**: Choose language, CWEs, mode, and context lines via simple prompts.
- **Automatic Path Configuration**: Automatically sets the correct project and JSON directories based on the selected language.
- **Structured Output**: Creates organized output directories (e.g., `rm_output/python_call`) based on your choices.
- **Validation**: Checks for valid inputs and existing directories.

## 🛠 Usage

Run the script directly from the terminal:

```bash
python3 interactive_runner.py
```

### Step-by-Step Guide

1.  **Select Language**:
    - The script lists available languages in the `projects/` directory.
    - Enter the number corresponding to your choice (e.g., `1` for python).

2.  **Select CWEs**:
    - Enter the CWE IDs you want to process, separated by spaces.
    - Default is `327`.
    - Example: `327 078 022`

3.  **Select Mode**:
    - Choose the deletion mode:
        - `call`: Removes the function call.
        - `caller`: Removes the calling function.
        - `bb`: Removes the basic block.

4.  **Context Lines**:
    - Specify how many extra lines to remove above and below the target.
    - Default is `0`.

5.  **Confirmation**:
    - Review your configuration.
    - Type `y` to proceed or `n` to abort.

## 📂 Output Structure

The output will be generated in `rm_output/` with a subdirectory name reflecting your configuration:

```
rm_output/
├── python_call/          # Language: python, Mode: call
│   ├── CWE-327/
│   └── ...
├── cpp_bb_a2_b2/         # Language: cpp, Mode: bb, Above: 2, Below: 2
│   └── ...
└── ...
```

## 🔧 Requirements

- Python 3.6+
- `batch_process_cwe.py` (must be in the same directory)
