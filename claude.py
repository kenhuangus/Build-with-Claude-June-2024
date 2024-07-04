import json
import subprocess
import anthropic
from dotenv import load_dotenv
import os

# Initialize Claude AI client
load_dotenv()
api_key = os.getenv('CLAUDE_API_KEY')
if not api_key:
    raise ValueError("CLAUDE_API_KEY not found in the environment variables")

client = anthropic.Client(api_key=api_key)


# Tool definitions
def code_analysis_tool(code_snippet):
    # Mock implementation
    analysis = {
        "complexity": len(code_snippet.split('\n')),
        "potential_issues": []
    }
    if 'SELECT' in code_snippet.upper():
        analysis["potential_issues"].append("Contains SELECT statement")
    return json.dumps(analysis)

def database_schema_tool(table_name):
    # Mock implementation
    mock_schema = {
        "users": ["id", "username", "password", "email"],
        "products": ["id", "name", "price", "category"],
        "orders": ["id", "user_id", "product_id", "quantity", "order_date"]
    }
    return json.dumps(mock_schema.get(table_name, {}))

def vulnerability_database_tool(vulnerability_type):
    # Mock implementation
    mock_cve = {
        "sql_injection": {
            "CVE-2024-1597": "SQL Injection vulnerability in Java JDBC",
            "CVE-2022-5678": "SQL Injection in Spring Framework"
        }
    }
    return json.dumps(mock_cve.get(vulnerability_type, {}))

def code_execution_tool(code_snippet):
    # CAUTION: This is a simplified example. In real-world use, ensure proper sandboxing.
    try:
        result = subprocess.run(['java', '-e', code_snippet], capture_output=True, text=True, timeout=5)
        return result.stdout
    except Exception as e:
        return f"Error executing code: {str(e)}"

def static_analysis_tool(file_path):
    # Mock implementation
    return json.dumps({
        "bugs": 2,
        "vulnerabilities": 1,
        "code_smells": 5
    })

async def analyze_and_fix_file_with_advanced_tools(file_path, vulnerabilities):
    print(f"Analyzing and fixing vulnerabilities in {file_path} using Claude tools...")
    
    with open(file_path, 'r') as file:
        content = file.read()
    
    vuln_summary = "\n".join([f"- Method: {method}, Line {line_number}: {line}" 
                              for _, method, line, line_number in vulnerabilities 
                              if _==file_path])
    
    prompt = f"""
    Analyze and fix the following Java file that contains potential SQL injection vulnerabilities:

    File: {file_path}

    Vulnerabilities found:
    {vuln_summary}

    Complete file content:
    ```java
    {content}
    ```

    You have access to the following tools:
    1. code_analysis_tool(code_snippet): Analyzes a code snippet and returns potential issues.
    2. database_schema_tool(table_name): Returns the schema for a given table.
    3. vulnerability_database_tool(vulnerability_type): Checks for known CVEs related to a vulnerability type.
    4. code_execution_tool(code_snippet): Executes a code snippet and returns the result.
    5. static_analysis_tool(file_path): Performs static analysis on the file.

    Use these tools as needed to perform a thorough analysis and provide fixes.

    Please provide:
    1. An explanation of each SQL injection risk, using the tools to support your analysis.
    2. A complete fixed version of the entire Java file that addresses all vulnerabilities.
    3. An explanation of why the fixed version is safer for each change made.
    4. Test cases to verify the fixes for each vulnerability.

    Format your response as follows:
    
    # Vulnerability Analysis
    [Your analysis here with complete vulnerable Java code rendered in markdown]

    # Fixed Java File
    ```java
    [Complete fixed Java file content here, make sure to have completed Java code in markdown]
    ```

    # Explanation of Fixes
    [Your explanation here]

    # Test Cases
    [Your test cases here]
    """

    response = await client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "code_analysis_tool",
                    "description": "Analyzes a code snippet and returns potential issues.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "code_snippet": {
                                "type": "string",
                                "description": "The code snippet to analyze"
                            }
                        },
                        "required": ["code_snippet"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "database_schema_tool",
                    "description": "Returns the schema for a given table.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "table_name": {
                                "type": "string",
                                "description": "The name of the table to get the schema for"
                            }
                        },
                        "required": ["table_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "vulnerability_database_tool",
                    "description": "Checks for known CVEs related to a vulnerability type.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "vulnerability_type": {
                                "type": "string",
                                "description": "The type of vulnerability to check for"
                            }
                        },
                        "required": ["vulnerability_type"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "code_execution_tool",
                    "description": "Executes a code snippet and returns the result.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "code_snippet": {
                                "type": "string",
                                "description": "The code snippet to execute"
                            }
                        },
                        "required": ["code_snippet"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "static_analysis_tool",
                    "description": "Performs static analysis on the file.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "The path to the file to analyze"
                            }
                        },
                        "required": ["file_path"]
                    }
                }
            }
        ]
    )
    
    return response.content[0].text

async def generate_security_report_with_advanced_tools(vulnerabilities, file_analyses):
    print("Generating security report using Claude tools...")
    
    vuln_summary = "\n".join([f"- {file}: {method} (Line {line_number})" for file, method, _, line_number in vulnerabilities])
    
    detailed_analyses = []
    for file_path, analysis in file_analyses.items():
        vulnerable_code_match = re.search(r'# Vulnerability Analysis\s*(.*?)# Fixed Java File', analysis, re.DOTALL)
        fixed_code_match = re.search(r'# Fixed Java File\s*```java\s*(.*?)\s*```', analysis, re.DOTALL)
        
        if vulnerable_code_match and fixed_code_match:
            vulnerable_code = vulnerable_code_match.group(1).strip()
            fixed_code = fixed_code_match.group(1).strip()
            
            detailed_analyses.append(f"""
## File: {file_path}

### Vulnerable Code
{vulnerable_code}

### Fixed Code
```java
{fixed_code}
```

### Analysis
{analysis}
""")
    
    detailed_analyses_str = "\n\n".join(detailed_analyses)
    
    prompt = f"""
    Generate a security report based on the following information:

    Vulnerabilities Found:
    {vuln_summary}

    Detailed File Analyses:
    {detailed_analyses_str}

    Please provide:
    1. An executive summary of the security state of the project.
    2. A detailed breakdown of each vulnerability found, including risk levels and potential impact.
    3. An action plan for addressing all identified issues, prioritized by risk level.
    4. Recommendations for improving the overall security posture of the project.

    Format your response as a well-structured markdown document suitable for presentation to both technical and non-technical stakeholders.
    Include the full vulnerable and fixed code for each file in your report.
    """

    response = await client.messages.create(
        model="claude-3-5-sonnet-20240620",
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    return response.content[0].text
