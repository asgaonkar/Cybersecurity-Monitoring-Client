import subprocess

def install(package):
    try:
        subprocess.call(['pip', 'install', package])
    except:
        unsuccessfull.append(package)

def upgrade(package):
    try:
        subprocess.call(['pip', 'install', package, '--upgrade'])
    except:
        unsuccessfull.append(package)

unsuccessfull = []
packages = []

with open('importPackages.txt') as f:
    for line in f:    
        packages.append(line)

print(packages)

for package in packages:
    install(package)
    upgrade(package)

print("\nUnsuccessfull: ",unsuccessfull)