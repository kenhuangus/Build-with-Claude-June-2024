# Vulnerability Scanner Using Claud AI Service

## Overview

This tool is a sophisticated Java SQL Injection Vulnerability Scanner that leverages static code analysis and AI-powered insights to detect, analyze, and provide fixes for potential SQL injection vulnerabilities in Java codebases. It uses Abstract Syntax Tree (AST) parsing to analyze Java source code, builds a call graph to understand method interactions, and utilizes the Claude AI model to provide in-depth analysis and suggested fixes.

## Features

- **Static Code Analysis**: Parses Java files using AST to detect potential SQL injection vulnerabilities.
- **Call Graph Generation**: Builds a call graph to understand the structure and flow of the codebase.
- **AI-Powered Analysis**: Uses Claude AI to analyze vulnerabilities, provide detailed explanations, and suggest fixes.
- **Comprehensive Reporting**: Generates a detailed markdown report of all findings, including:
  - Executive summary of the project's security state
  - Detailed breakdown of each vulnerability
  - Analysis of vulnerability propagation through the call graph
  - Action plan for addressing issues
  - Recommendations for improving overall security posture
- **Automated Fix Suggestions**: Provides AI-generated fixed versions of vulnerable code.
- **Test Case Generation**: Suggests test cases to verify vulnerability fixes.

## Prerequisites

- Python 3.7 or higher
- Access to the Claude AI API (API key required)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/kenhuangus/Build-with-Claude-June-2024.git
   cd Build-with-Claude-June-2024
   ```

2. Install the required Python packages:
   ```
   pip install javalang networkx anthropic python-dotenv
   ```

3. Create a `.env` file in the project root and add your Claude API key:
   ```
   CLAUDE_API_KEY=your_api_key_here
   ```

## Usage

1. Place the Java files you want to analyze in the same directory as the script or in subdirectories.

2. Run the scanner:
   ```
   python sast.py
   ```

3. The script will analyze all Java files in the current directory and its subdirectories. It will output its progress to the console and generate two types of files:
   - `fixed_*.java`: Fixed versions of files with detected vulnerabilities.
   - `security_report.md`: A comprehensive security report of all findings.

## Output

- **Console Output**: The script will print its progress, including files being analyzed and vulnerabilities found.
- **Fixed Files**: For each file with detected vulnerabilities, a `fixed_` version will be created in the same directory.
- **Security Report**: A detailed `java_security_report.md` file will be generated, containing all findings and recommendations.

## Limitations

- The tool focuses on SQL injection vulnerabilities and may not detect other types of security issues.
- The effectiveness of the analysis and suggested fixes depends on the capabilities of the Claude AI model.
- Large codebases may take significant time to analyze due to the AI-powered analysis step.

## Contributing

Contributions to improve the scanner are welcome. Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes with clear, descriptive messages.
4. Push the branch and open a pull request with a detailed description of your changes.

## License

MIT

## Disclaimer

This tool is provided for educational and research purposes only. Always verify the results and suggested fixes manually before applying them to production code. The authors are not responsible for any misuse or damage caused by this tool.
