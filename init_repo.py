#!/usr/bin/env python
"""
Budget Wise Repository Initialization Script
This script helps set up the Git repository structure for the Budget Wise project.
"""
import os
import subprocess
import sys

def run_command(command):
    """Run a shell command and print output."""
    print(f"Running: {command}")
    try:
        result = subprocess.run(command, shell=True, check=True, 
                              capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing: {command}")
        print(f"Error message: {e.stderr}")
        return False

def check_git_installed():
    """Check if Git is installed."""
    return run_command("git --version")

def init_git_repo():
    """Initialize the Git repository."""
    commands = [
        "git init",
        "git add .",
        "git commit -m 'Initial commit: Budget Wise project structure'",
    ]
    
    for command in commands:
        if not run_command(command):
            return False
    return True

def create_instance_folder():
    """Create the instance folder for the database."""
    if not os.path.exists('instance'):
        os.makedirs('instance')
        print("Created instance folder")
    else:
        print("Instance folder already exists")

def main():
    """Main function to initialize the repository."""
    print("Budget Wise Repository Initialization")
    print("====================================")
    
    # Check if Git is installed
    if not check_git_installed():
        print("Git is not installed or not in PATH. Please install Git and try again.")
        sys.exit(1)
    
    # Create instance folder
    create_instance_folder()
    
    # Initialize Git repository
    if init_git_repo():
        print("\nRepository successfully initialized!")
        print("\nNext steps:")
        print("1. Set up your remote repository:")
        print("   git remote add origin https://github.com/your-username/budget-wise.git")
        print("2. Push your code:")
        print("   git push -u origin main")
    else:
        print("\nFailed to initialize repository.")
        sys.exit(1)

if __name__ == "__main__":
    main() 