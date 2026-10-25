import subprocess

command = input("command name: ")
subprocess.run(["printf", "%s", command], check=True)
