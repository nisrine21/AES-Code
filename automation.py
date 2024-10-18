import os
import subprocess

# Directory to search for files
directory = "C:\\Users\\xapa\\Documents\\test\\enc"  # Current directory; change this if needed

# Define the file extensions to encrypt
file_extensions = ['.txt', '.pdf', '.jpg', '.jpeg', '.png']

# Look for files that end with the specified extensions but not with '_E' before the extension
for filename in os.listdir(directory):
    # Check each extension
    for ext in file_extensions:
        if filename.lower().endswith(ext) and not filename.lower().endswith('_·' + ext):
            try:
                # Execute the "enc.py" script if a valid file is found
                subprocess.run(["python", "enc_total.py"], check=True)
                print(f"enc.py executed successfully for {filename}.")
            except subprocess.CalledProcessError as e:
                print(f"Failed to execute enc_total.py for {filename}: {e}")
            break  # Exit the extensions loop after finding a matching extension
    else:
        continue  # Continue if no break occurred in the extensions loop
    break  # Exit the files loop after processing the first matching file
else:
    print("No suitable files found.")