#!/bin/bash

# Create a virtual environment
python3 -m venv MyEnv

# Activate the virtual environment
source MyEnv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install required libraries from requirements.txt
pip install -r requirements.txt

# Install any additional packages you may need in the future
# Example:
# pip install some-library

echo "Setup complete! Your environment is ready."
