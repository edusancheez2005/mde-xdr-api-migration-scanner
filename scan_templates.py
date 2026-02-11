#!/usr/bin/env python3

# ============================================================================
# LEGACY API SCANNER - Scans playbook templates for deprecated MDE/XDR APIs
# ============================================================================
# HOW TO USE:
#   1. Run: python scan_templates.py
#   2. Enter a local folder path OR a GitHub URL
#   3. If scanning GitHub, enter your GitHub Personal Access Token when asked
#   4. Check the output CSV file
#
# REQUIREMENTS:
#   - For GitHub scanning: pip install requests
#
# GITHUB TOKEN (required for private repos):
#   1. Go to: https://github.com/settings/tokens
#   2. Click "Generate new token" > "Generate new token (classic)"
#   3. Give it a name like "API Scanner"
#   4. Select scope: "repo" (for private repos)
#   5. Click "Generate token" and copy it
#   6. Paste it when the script asks for it
# ============================================================================

import csv
import json
import os
import re

# Try to import requests - only needed if you want to scan GitHub repos directly
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ============================================================================
# CONFIGURATION - Edit these lists to add/remove patterns to search for
# ============================================================================

# Old API base URLs that are being retired
LEGACY_BASES = [
    "api.securitycenter.microsoft.com",   # Old MDE API
    "api.security.microsoft.com",         # Old Defender XDR API
]

# Old Logic App connector names
LEGACY_CONNECTORS = [
    "MicrosoftDefenderATP",
    "shared_windowsdefenderatp",
]

# Old API endpoint paths (regex patterns)
LEGACY_ENDPOINT_PATTERNS = [
    r"/api/machines/[^/\s]+/isolate\b",
    r"/api/machines/[^/\s]+/unisolate\b",
    r"/api/machines/[^/\s]+/runAntiVirusScan\b",
    r"/api/machines/[^/\s]+/offboard\b",
    r"/api/machines/[^/\s]+\b",
    r"/api/vulnerabilities\b",
    r"/api/machines/[^/\s]+/vulnerabilities\b",
    r"/api/exposureScore\b",
    r"/api/alerts\b",
    r"/api/alerts/[^/\s]+\b",
    r"/api/incidents\b",
    r"/api/incidents/[^/\s]+/comments\b",
    r"/api/advancedqueries/run\b",
    r"/api/evidence\b",
]

# File extensions to scan
FILE_EXTENSIONS = (".json", ".template.json", ".arm.json", ".bicep")

# Output file name
OUTPUT_FILE = "legacy_api_findings.csv"



# HELPER FUNCTIONS

# try_parse_json - Safely parse JSON text, returns None if invalid (so we don't crash on non-JSON files)
def try_parse_json(text):
    try:
        return json.loads(text)
    except:
        return None


# extract_all_strings - Dig through a JSON object and pull out every string value with its path
# We need this because ARM templates are deeply nested - a legacy URL might be buried inside
# $.resources[0].properties.definition.actions.HTTP.inputs.uri
# Returns a list of tuples like: [("$.actions.HTTP.uri", "https://api.security..."), ...]
# We use tuples because they're simple pairs of (path, value) that we don't need to modify
def extract_all_strings(obj, path="$"):
    results = []
    
    # If it's a dictionary (like {"key": "value"}), loop through each key and go deeper
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = path + "." + key
            results.extend(extract_all_strings(value, new_path))
    
    # If it's a list (like ["item1", "item2"]), loop through each index and go deeper
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            new_path = path + "[" + str(i) + "]"
            results.extend(extract_all_strings(value, new_path))
    
    # If it's a string, we found what we're looking for - save it with its path
    elif isinstance(obj, str):
        results.append((path, obj))
    
    # Numbers, booleans, null are ignored - we only care about strings
    return results


# scan_content - Scan file content for legacy API patterns and return a list of findings
def scan_content(file_name, file_path, content):
    findings = []
    
    # Try to parse as JSON first
    parsed = try_parse_json(content)
    
    # If it's valid JSON, scan all the string values we extracted
    if parsed is not None:
        all_strings = extract_all_strings(parsed)
        
        for json_path, string_value in all_strings:
            
            # Check for legacy base URLs
            for base in LEGACY_BASES:
                if base in string_value:
                    findings.append({
                        "file": file_name,
                        "path": file_path,
                        "match_type": "legacy_base",
                        "matched": base,
                        "location": json_path
                    })
            
            # Check for legacy connectors
            for connector in LEGACY_CONNECTORS:
                if connector in string_value:
                    findings.append({
                        "file": file_name,
                        "path": file_path,
                        "match_type": "legacy_connector",
                        "matched": connector,
                        "location": json_path
                    })
            
            # Check for legacy endpoint patterns using regex
            for pattern in LEGACY_ENDPOINT_PATTERNS:
                if re.search(pattern, string_value, flags=re.IGNORECASE):
                    findings.append({
                        "file": file_name,
                        "path": file_path,
                        "match_type": "legacy_endpoint",
                        "matched": pattern,
                        "location": json_path
                    })
    
    # Also do a raw text scan to catch things in comments or non-JSON files like .bicep
    for base in LEGACY_BASES:
        if base in content:
            findings.append({
                "file": file_name,
                "path": file_path,
                "match_type": "legacy_base",
                "matched": base,
                "location": "(raw text)"
            })
    
    for connector in LEGACY_CONNECTORS:
        if connector in content:
            findings.append({
                "file": file_name,
                "path": file_path,
                "match_type": "legacy_connector",
                "matched": connector,
                "location": "(raw text)"
            })
    
    for pattern in LEGACY_ENDPOINT_PATTERNS:
        if re.search(pattern, content, flags=re.IGNORECASE):
            findings.append({
                "file": file_name,
                "path": file_path,
                "match_type": "legacy_endpoint",
                "matched": pattern,
                "location": "(raw text)"
            })
    
    # Removing duplicates by using a dictionary with a unique key for each finding
    unique = {}
    for f in findings:
        key = (f["path"], f["match_type"], f["matched"], f["location"])
        unique[key] = f
    
    return list(unique.values())


# LOCAL FOLDER SCANNING

# get_local_files - Walk through a folder and return all file paths that match our extensions
def get_local_files(folder_path):
    files_found = []
    
    for folder, subfolders, files in os.walk(folder_path):
        for file_name in files: # if the filename ends with .json, .template.json, .arm.json, or .bicep, we want to scan it
            if file_name.lower().endswith(FILE_EXTENSIONS):
                full_path = os.path.join(folder, file_name)
                files_found.append(full_path)
    
    return files_found


# scan_local_folder - Scan all matching files in a local folder and return findings
def scan_local_folder(folder_path):
    print("")
    print("Scanning local folder: " + folder_path)
    print("Looking for: .json, .template.json, .arm.json, .bicep files")
    print("")
    
    files = get_local_files(folder_path)
    print("Found " + str(len(files)) + " files to scan...")
    print("")
    
    all_findings = []
    for i, file_path in enumerate(files):
        if (i + 1) % 100 == 0:
            print("Scanned " + str(i + 1) + " files...")
        
        file_name = os.path.basename(file_path)
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        file_findings = scan_content(file_name, file_path, content)
        all_findings.extend(file_findings)
    
    return all_findings, len(files)


# GITHUB REPO SCANNING - Scans directly via GitHub API, no cloning needed
# This is much faster for large repos and works even if you don't have write access to the repo.

# parse_github_url - Extract owner and repo name from various GitHub URL formats
def parse_github_url(url):
    url = url.strip().rstrip("/")
    
    # Remove https:// or http://
    if url.startswith("https://"):
        url = url[8:]
    elif url.startswith("http://"):
        url = url[7:]
    
    # Remove github.com/
    if url.startswith("github.com/"):
        url = url[11:]
    
    # Now we have "owner/repo" - split it
    parts = url.split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    
    return None, None


# get_github_tree - Use GitHub API to get list of all files in a repo (requires token for private repos)
def get_github_tree(owner, repo, token, branch="main"):
    branches_to_try = [branch, "main", "master"] #can change depending on the branch naming convention of the repo, but these are the most common ones. We will try them in order until we find one that works.
    
    # Set up headers with the token for authentication
    headers = {"Authorization": "token " + token}
    
    for branch_name in branches_to_try:
        url = "https://api.github.com/repos/" + owner + "/" + repo + "/git/trees/" + branch_name + "?recursive=1"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            files = []
            
            for item in data.get("tree", []):
                if item.get("type") == "blob":  # blob = file, tree = folder
                    file_path = item.get("path", "")
                    if file_path.lower().endswith(FILE_EXTENSIONS):
                        files.append(file_path)
            
            return files, branch_name
        
        elif response.status_code == 401:
            print("ERROR: Invalid GitHub token. Check your token and try again.")
            return [], None
        elif response.status_code == 404:
            continue  # Try next branch
    
    return [], None


# get_github_file_content - Download a single file's content from GitHub (requires token for private repos)
def get_github_file_content(owner, repo, file_path, branch, token):
    # For private repos, we need to use the API endpoint with auth instead of raw.githubusercontent.com
    url = "https://api.github.com/repos/" + owner + "/" + repo + "/contents/" + file_path + "?ref=" + branch
    headers = {"Authorization": "token " + token, "Accept": "application/vnd.github.v3.raw"} #using the token for authorisation
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.text
    return None


# scan_github_repo - Scan a GitHub repo directly without cloning it locally
def scan_github_repo(github_url):
    if not REQUESTS_AVAILABLE:
        print("")
        print("ERROR: To scan GitHub repos, install requests: pip install requests")
        print("")
        return [], 0
    
    owner, repo = parse_github_url(github_url)
    
    if not owner or not repo:
        print("")
        print("ERROR: Could not parse GitHub URL. Use format: https://github.com/owner/repo")
        print("")
        return [], 0
    
    # Ask for GitHub token (required for private repos)
    print("")
    print("GitHub Personal Access Token is required (especially for private repos).")
    print("To create one: https://github.com/settings/tokens > Generate new token (classic) > select 'repo' scope")
    print("")
    token = input("Enter your GitHub token: ").strip()
    
    if not token:
        print("ERROR: GitHub token is required.")
        return [], 0
    
    print("")
    print("Scanning GitHub repo: " + owner + "/" + repo)
    print("(No cloning needed - scanning directly via GitHub API)")
    print("")
    
    print("Getting file list from GitHub...")
    files, branch = get_github_tree(owner, repo, token)
    
    if not files:
        print("ERROR: Could not get files from repo. Check the URL and token, and try again.")
        return [], 0
    
    print("Found " + str(len(files)) + " files to scan (branch: " + branch + ")")
    print("")
    
    all_findings = []
    for i, file_path in enumerate(files):
        if (i + 1) % 50 == 0:
            print("Scanned " + str(i + 1) + " of " + str(len(files)) + " files...")
        
        content = get_github_file_content(owner, repo, file_path, branch, token)
        
        if content:
            file_name = os.path.basename(file_path)
            github_path = "github.com/" + owner + "/" + repo + "/" + file_path
            file_findings = scan_content(file_name, github_path, content)
            all_findings.extend(file_findings)
    
    return all_findings, len(files)



# OUTPUT FUNCTIONS


# write_results - Write all findings to a CSV file
def write_results(all_findings):
    all_findings.sort(key=lambda x: (x["path"], x["match_type"], x["matched"]))
    
    columns = ["file", "path", "match_type", "matched", "location"]
    
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for finding in all_findings:
            writer.writerow(finding)


# print_summary - Print a summary of what was found
def print_summary(all_findings, files_scanned):
    print("")
    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print("")
    print("Files scanned: " + str(files_scanned))
    print("Legacy API matches found: " + str(len(all_findings)))
    print("Results saved to: " + OUTPUT_FILE)
    print("")
    
    if all_findings:
        # Count by match type
        counts = {}
        for f in all_findings:
            mt = f["match_type"]
            if mt not in counts:
                counts[mt] = 0
            counts[mt] = counts[mt] + 1
        
        print("Breakdown:")
        for match_type, count in counts.items():
            print("  " + match_type + ": " + str(count))
        print("")
        
        # List affected files (max 20)
        affected_files = set()
        for f in all_findings:
            affected_files.add(f["file"])
        
        print("Affected files (" + str(len(affected_files)) + "):")
        for file_name in sorted(list(affected_files))[:20]:
            print("  - " + file_name)
        
        if len(affected_files) > 20:
            print("  ... and " + str(len(affected_files) - 20) + " more (see CSV)")


# MAIN


def main():
    print("")
    print("=" * 60)
    print("LEGACY API SCANNER")
    print("Find deprecated MDE/XDR APIs in playbook templates")
    print("=" * 60)
    print("")
    print("You can enter:")
    print("  - A local folder path (e.g., C:\\repos\\Azure-Sentinel)")
    print("  - A GitHub URL (e.g., https://github.com/Azure/Azure-Sentinel)")
    print("")
    
    user_input = input("Enter folder path or GitHub URL: ").strip()
    
    # Remove quotes if user wrapped the path in quotes
    if user_input.startswith('"') and user_input.endswith('"'):
        user_input = user_input[1:-1]
    if user_input.startswith("'") and user_input.endswith("'"):
        user_input = user_input[1:-1]
    
    # Figure out if it's a GitHub URL or local folder
    is_github = "github.com" in user_input.lower() or (
        "/" in user_input and 
        not os.path.exists(user_input) and 
        not "\\" in user_input
    )
    
    if is_github:
        all_findings, files_scanned = scan_github_repo(user_input)
    else:
        if not os.path.isdir(user_input):
            print("")
            print("ERROR: Folder not found: " + user_input)
            return
        all_findings, files_scanned = scan_local_folder(user_input)
    
    if files_scanned == 0:
        return
    
    write_results(all_findings)
    print_summary(all_findings, files_scanned)


if __name__ == "__main__":
    main()
