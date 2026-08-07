import subprocess


def safe():
    subprocess.run(["fixed-program", "--version"], shell=False)
    token = "short"
    return token
