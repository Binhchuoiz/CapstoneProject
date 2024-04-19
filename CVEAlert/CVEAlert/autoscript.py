import os
import requests
import zipfile
import time

# Set the path to your desired folder where you want to save the new CVEs
destination_folder = "D:/TestAuto"

# Function to check for new releases and download assets
def check_for_new_release():
    print("Checking for new releases...")

    try:
        # Get the latest release information
        response = requests.get("https://api.github.com/repos/CVEProject/cvelistV5/releases/latest")
        response.raise_for_status()  # Raise an error for failed responses
        release_info = response.json()

        # Get the tag name of the latest release
        latest_release_tag = release_info.get("tag_name")
        print("Latest release tag:", latest_release_tag)

        # Continue with the rest of the function...
    
    except requests.exceptions.RequestException as e:
        print("Error retrieving latest release information:", e)
        return False

# Function to run specified commands
def run_commands():
    print("Running specified commands...")
    os.environ["PYTHONPATH"] = "D:/Đồ án/trueCaps/CVEAlert;" + os.environ.get("PYTHONPATH", "")
    os.system('"d:/Đồ án/trueCaps/CVEAlert/.venv/Scripts/python.exe" "d:/Đồ án/trueCaps/CVEAlert/CVEAlert/scriptTest.py"')

# Loop indefinitely to continuously check for new releases
while True:
    # Check for new releases and download assets
    if check_for_new_release():
        # If assets are successfully downloaded, run the specified commands
        run_commands()
    # Sleep for 1 hour before checking again
    print("Sleeping for 1 hour...")
    time.sleep(3600)