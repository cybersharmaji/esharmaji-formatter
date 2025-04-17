# Set identity once
git config --global user.name "cybersharmaji"
git config --global user.email "cybersharmaji@gmail.com"

# Make sure you're in the repo folder
cd ~/esharmaji-formatter

# Initialize only if not already done
git init

# Add and commit all files
git add .
git commit -m "Initial commit: Esharmaji Formatter"

# Rename to main (if not done)
git branch -M main

# Push to GitHub
git push -u origin main
