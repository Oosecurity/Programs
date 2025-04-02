import os
import glob

def read_files_from_folder(folder_path):
    # Use glob to match all files in the folder
    file_paths = glob.glob(os.path.join(folder_path, '*'))
    file_contents = {}

    # Loop through each file
    for file_path in file_paths:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                # Read the file and store the content in a dictionary with filename as the key
                file_contents[os.path.basename(file_path)] = file.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
    
    return file_contents

# Example usage
folder_path = r'C:\Users\Oscar\Downloads'
file_data = read_files_from_folder(folder_path)

# Now 'file_data' contains file names as keys and their contents as values
for filename, content in file_data.items():
    print(f"File: {filename}\nContent: {content}\n")
