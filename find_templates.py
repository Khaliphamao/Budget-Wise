import os

# Get the absolute path to the current directory
current_dir = os.path.abspath(os.path.dirname(__file__))
print(f"Current directory: {current_dir}")

# Check if the templates directory exists
templates_path = os.path.join(current_dir, 'app', 'templates')
print(f"Templates path: {templates_path}")
print(f"Templates directory exists: {os.path.isdir(templates_path)}")

# List files in the templates directory
if os.path.isdir(templates_path):
    print("Files in templates directory:")
    for file in os.listdir(templates_path):
        print(f"  - {file}")

# Also try the alternative path
alt_templates_path = os.path.join(current_dir, 'templates')
print(f"Alternative templates path: {alt_templates_path}")
print(f"Alternative templates directory exists: {os.path.isdir(alt_templates_path)}")

if os.path.isdir(alt_templates_path):
    print("Files in alternative templates directory:")
    for file in os.listdir(alt_templates_path):
        print(f"  - {file}") 