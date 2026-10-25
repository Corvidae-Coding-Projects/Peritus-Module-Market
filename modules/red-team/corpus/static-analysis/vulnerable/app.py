import subprocess
import yaml

command = input("command: ")
subprocess.run(command, shell=True)
payload = input("expression: ")
print(eval(payload))
print(yaml.load(payload))
