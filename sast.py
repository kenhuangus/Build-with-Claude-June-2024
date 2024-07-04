import os
import re
import javalang
import networkx as nx
import anthropic
from dotenv import load_dotenv
import json
import asyncio

# Initialize Claude AI client
load_dotenv()
api_key = os.getenv('CLAUDE_API_KEY')
if not api_key:
    raise ValueError("CLAUDE_API_KEY not found in the environment variables")

client = anthropic.Client(api_key=api_key)

# Flag to use advanced Claude tools
USE_ADVANCED_CLAUDE_TOOLS = False  # Set this to True to use advanced Claude tools

# Define SQL methods to check for vulnerabilities (all lowercase)
SQL_METHODS = [
    'executequery', 'select', 'executeupdate', 'execute', 'executebatch', 'executelargeupdate',
    'preparestatement', 'preparecall', 'query', 'raw', 'exec', 'exec_', 'execute_sql',
    'rawquery', 'raw_query', 'from_sql', 'fromsql', 'callprocedure', 'call',
    'find', 'aggregate', 'executescalar', 'executenonquery', 'executereader',
    'createnativequery', 'createsqlquery', 'createstatement', 'createpreparedstatement',
    'executebatch', 'executelargebatch', 'executetransaction', 'runtransaction'
]

def find_files(directory):
    print(f"Searching for Java files in directory: {directory}")
    java_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".java"):
                java_files.append(os.path.join(root, file))
    print(f"Found {len(java_files)} Java files")
    return java_files

def parse_java_file(file_path):
    print(f"Parsing Java file: {file_path}")
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        tree = javalang.parse.parse(content)
        return tree, content
    except Exception as e:
        print(f"Error parsing Java file {file_path}: {e}")
        return None, None

def build_call_graph(tree, file_path):
    G = nx.DiGraph()
    class_name = ""
    
    for path, node in tree:
        if isinstance(node, javalang.tree.ClassDeclaration):
            class_name = node.name
        elif isinstance(node, javalang.tree.MethodDeclaration):
            method_name = f"{class_name}.{node.name}"
            G.add_node(method_name, file=file_path)
            for _, child in node.filter(javalang.tree.MethodInvocation):
                called_method = f"{child.qualifier}.{child.member}" if child.qualifier else child.member
                G.add_edge(method_name, called_method)
    
    return G

def check_sql_injection_via_ast(tree, content, file_path, call_graph):
    vulnerabilities = []
    
    for path, node in tree.filter(javalang.tree.MethodInvocation):
        if node.member.lower() in SQL_METHODS:
            for argument in node.arguments:
                if isinstance(argument, javalang.tree.BinaryOperation):
                    if any(isinstance(operand, javalang.tree.MemberReference) for operand in [argument.operandl, argument.operandr]):
                        line_number = node.position.line if node.position else -1
                        line = content.split('\n')[line_number - 1] if line_number > 0 else ""
                        method_name = next((method for method, data in call_graph.nodes(data=True) if data['file'] == file_path), "Unknown")
                        vulnerability = (file_path, method_name, node.member, line, line_number)
                        vulnerabilities.append(vulnerability)
                        print(f"AST Vulnerability found: {vulnerability}")
    
    return vulnerabilities

def check_sql_injection_via_call_graph(call_graph, content, file_path):
    vulnerabilities = []
    
    for node in call_graph.nodes:
        method_name = node.split('.')[-1].lower()
        if method_name in SQL_METHODS:
            line_number = -1
            line = ""
            for line_number, line in enumerate(content.split('\n'), start=1):
                if re.search(rf"\b{method_name}\b", line, re.IGNORECASE):
                    break
            vulnerability = (file_path, node, method_name, line, line_number)
            vulnerabilities.append(vulnerability)
            print(f"Call Graph Vulnerability found: {vulnerability}")
    
    return vulnerabilities

def check_sql_injection_via_string_matching(content, file_path):
    vulnerabilities = []
    lines = content.split('\n')
    
    for line_number, line in enumerate(lines, start=1):
        for method in SQL_METHODS:
            if re.search(rf"\b{method}\b", line, re.IGNORECASE):
                vulnerability = (file_path, "Unknown", method, line, line_number)
                vulnerabilities.append(vulnerability)
                print(f"String Matching Vulnerability found: {vulnerability}")
    
    return vulnerabilities

def check_vulnerabilities(files):
    all_vulnerabilities = []
    full_call_graph = nx.DiGraph()
    
    for file_path in files:
        tree, content = parse_java_file(file_path)
        if tree and content:
            file_call_graph = build_call_graph(tree, file_path)
            full_call_graph = nx.compose(full_call_graph, file_call_graph)
            
            # Accumulate vulnerabilities from three methods
            vulnerabilities_ast = check_sql_injection_via_ast(tree, content, file_path, file_call_graph)
            vulnerabilities_call_graph = check_sql_injection_via_call_graph(file_call_graph, content, file_path)
            vulnerabilities_string = check_sql_injection_via_string_matching(content, file_path)
            
            all_vulnerabilities.extend(vulnerabilities_ast)
            all_vulnerabilities.extend(vulnerabilities_call_graph)
            all_vulnerabilities.extend(vulnerabilities_string)
    
    return all_vulnerabilities, full_call_graph

async def analyze_and_fix_file(file_path, vulnerabilities, call_graph):
    print(f"Analyzing and fixing vulnerabilities in {file_path}...")
    
    with open(file_path, 'r') as file:
        content = file.read()
    
    vuln_summary = "\n".join([f"- Method: {method}, SQL Method: {sql_method}, Line {line_number}: {line}" 
                              for _, method, sql_method, line, line_number in vulnerabilities 
                              if _==file_path])
    
    call_graph_str = "\n".join([f"{u} -> {v}" for u, v in call_graph.edges() if call_graph.nodes[u]['file'] == file_path])
    
    prompt = f"""
    Analyze and fix the following Java file that contains potential SQL injection vulnerabilities:

    File: {file_path}

    Vulnerabilities found:
    {vuln_summary}

    Call Graph for this file:
    {call_graph_str}

    Complete file content:
    ```java
    {content}
    ```

    Please provide:
    1. An explanation of each SQL injection risk, considering the call graph. Especially focus on false positive. For example, if Prepared statements are used, then it is a false positive, and you only need to skip this and give response to say why it is false positive.
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
    
   # print(f"Prompt sent to Claude:\n{prompt}")

    response = await asyncio.to_thread(
        client.messages.create,
        model="claude-3-5-sonnet-20240620",
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    analysis = response.content[0].text

    if USE_ADVANCED_CLAUDE_TOOLS:
        advanced_analysis = await analyze_and_fix_file_with_advanced_tools(file_path, vulnerabilities, call_graph)
        analysis += "\n\n# Advanced Analysis (using Claude tools)\n" + advanced_analysis

    return analysis

async def generate_security_report(vulnerabilities, file_analyses, full_call_graph):
    print("Generating security report...")
    
    vuln_summary = "\n".join([f"- {file}: {method} (SQL Method: {sql_method}, Line {line_number})" 
                              for file, method, sql_method, _, line_number in vulnerabilities])
    
    call_graph_str = "\n".join([f"{u} -> {v}" for u, v in full_call_graph.edges()])
    
    prompt = f"""
    Generate a security report based on the following information:

    Vulnerabilities Found:
    {vuln_summary}

    Full Call Graph:
    {call_graph_str}

    Detailed File Analyses:
    {json.dumps(file_analyses, indent=2)}

    Please provide:
    1. An executive summary of the security state of the project.
    2. A detailed breakdown of each vulnerability found, including risk levels and potential impact.
    3. An analysis of how vulnerabilities might propagate through the call graph.
    4. An action plan for addressing all identified issues, prioritized by risk level.
    5. Recommendations for improving the overall security posture of the project.

    Format your response as a well-structured markdown document suitable for presentation to both technical and non-technical stakeholders.
    Include the full vulnerable and fixed code for each

    """

    response = await asyncio.to_thread(
        client.messages.create,
        model="claude-3-5-sonnet-20240620",
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    report = response.content[0].text

    if USE_ADVANCED_CLAUDE_TOOLS:
        advanced_report = await generate_security_report_with_advanced_tools(vulnerabilities, file_analyses, full_call_graph)
        report += "\n\n# Advanced Security Analysis (using Claude tools)\n" + advanced_report

    return report

def save_fixed_file(file_path, fixed_content):
    dir_path = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    fixed_file_path = os.path.join(dir_path, f"fixed_{file_name}")
    
    with open(fixed_file_path, 'w') as file:
        file.write(fixed_content)
    
    print(f"Fixed file saved as: {fixed_file_path}")

async def main():
    try:
        current_directory = os.getcwd()
        java_files = find_files(current_directory)
        
        vulnerabilities, full_call_graph = check_vulnerabilities(java_files)

        if not vulnerabilities:
            print("No vulnerabilities found.")
            return

        print(f"Found {len(vulnerabilities)} potential vulnerabilities. Analyzing and fixing...")

        file_analyses = {}
        for file_path in set(vuln[0] for vuln in vulnerabilities):
            file_vulnerabilities = [v for v in vulnerabilities if v[0] == file_path]
            file_analysis = await analyze_and_fix_file(file_path, file_vulnerabilities, full_call_graph)
            file_analyses[file_path] = file_analysis

            fixed_content_match = re.search(r'```java\n(.*?)```', file_analysis, re.DOTALL)
            if fixed_content_match:
                fixed_content = fixed_content_match.group(1)
                save_fixed_file(file_path, fixed_content)

        security_report = await generate_security_report(vulnerabilities, file_analyses, full_call_graph)
        report_path = os.path.join(current_directory, "security_report.md")
        
        with open(report_path, 'w') as report_file:
            report_file.write(security_report)
        
        print(f"Security report generated and saved as: {report_path}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(main())
