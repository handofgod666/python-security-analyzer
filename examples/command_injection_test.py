"""
Test cases for Command Injection detection
"""
import os
import subprocess

# VULNERABLE: os.system with user input
def vulnerable_os_system():
    filename = input("Enter filename: ")
    os.system(f"cat {filename}")  # Command injection!

# VULNERABLE: subprocess with shell=True
def vulnerable_subprocess_shell():
    user_input = input("Enter command: ")
    subprocess.run(f"ls {user_input}", shell=True)  # Command injection!

# VULNERABLE: subprocess.call with concatenation
def vulnerable_subprocess_concat():
    user_file = input("File: ")
    subprocess.call("grep pattern " + user_file, shell=True)  # Command injection!

# VULNERABLE: os.popen with f-string
def vulnerable_popen():
    directory = input("Directory: ")
    os.popen(f"ls -la {directory}")  # Command injection!

# VULNERABLE: eval with user input
def vulnerable_eval():
    user_code = input("Enter expression: ")
    result = eval(user_code)  # Code injection!

# VULNERABLE: exec with user input
def vulnerable_exec():
    user_code = input("Enter code: ")
    exec(user_code)  # Code injection!

# VULNERABLE: subprocess.check_output with shell=True
def vulnerable_check_output():
    hostname = input("Enter hostname: ")
    output = subprocess.check_output(f"ping -c 1 {hostname}", shell=True)

# VULNERABLE: .format() with command
def vulnerable_format():
    target = input("Target: ")
    cmd = "nmap {}".format(target)
    os.system(cmd)

# SAFE: subprocess with list arguments (no shell)
def safe_subprocess_list():
    user_file = input("File: ")
    subprocess.run(["cat", user_file])  # Safe!

# SAFE: subprocess with shell=False
def safe_subprocess_no_shell():
    user_input = input("Search term: ")
    subprocess.run(["grep", user_input, "file.txt"], shell=False)  # Safe!

# SAFE: Hardcoded commands
def safe_hardcoded():
    os.system("ls -la /tmp")  # Safe - no user input
    subprocess.run("date", shell=True)  # Safe - no user input

# SAFE: Using list with subprocess.Popen
def safe_popen_list():
    user_arg = input("Argument: ")
    proc = subprocess.Popen(["echo", user_arg])  # Safe!

# VULNERABLE: Chained with tainted data
def vulnerable_chained():
    user_input = input("Enter value: ")
    command = user_input
    os.system(command)  # Command injection via tainted variable!

# VULNERABLE: subprocess.run with f-string and shell
def vulnerable_run_fstring():
    port = input("Port: ")
    subprocess.run(f"netstat -an | grep {port}", shell=True)

# SAFE: subprocess.run with list and no shell
def safe_run_list():
    search_term = input("Search: ")
    subprocess.run(["grep", "-r", search_term, "/var/log"])

# VULNERABLE: Multiple variables
def vulnerable_multiple_vars():
    host = input("Host: ")
    port = input("Port: ")
    os.system(f"nc -zv {host} {port}")

# SAFE: Constants only
def safe_constants():
    LOG_DIR = "/var/log"
    subprocess.run(["ls", "-la", LOG_DIR])
