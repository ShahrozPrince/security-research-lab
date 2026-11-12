
# Intentionally insecure practice code.
# For local security testing only. Do not deploy.

import os

def run_command():
    cmd = input("Enter command: ")
    os.system(cmd)  # Command injection risk

if __name__ == "__main__":
    run_command()
