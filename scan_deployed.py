#!/usr/bin/env python3

# LEGACY API SCANNER - Scans deployed Logic Apps in Azure for deprecated MDE/XDR APIs
#
# HOW TO USE:
#   1. Run: az login (to authenticate with Azure)
#   2. Run: python scan_deployed.py
#   3. Enter your subscription ID when asked
#   4. Check the output CSV file
#
# WHAT YOU NEED:
#   - Azure CLI installed and logged in (az login)
#   - Reader access to the subscription
#   - Python packages: pip install azure-identity azure-mgmt-resource
#
# HOW THIS SCRIPT WORKS (the flow):
#   1. You login to Azure using "az login" in your terminal
#   2. The script uses DefaultAzureCredential to pick up that login automatically
#   3. It connects to Azure Resource Manager (ARM) - this is the management layer for all Azure resources
#   4. It lists ALL resources in your subscription and filters for Logic Apps (type: microsoft.logic/workflows)
#   5. For each Logic App, it fetches the "workflow definition" - this is the JSON that describes what the Logic App does
#   6. It scans that JSON for legacy API patterns
#   7. Outputs findings to a CSV file

import csv
import re

# Azure SDK imports
# DefaultAzureCredential: Automatically finds your credentials from az login, VS Code, environment variables, etc.
# ResourceManagementClient: Lets us talk to Azure Resource Manager (ARM) to list and inspect resources
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient


# CONFIGURATION - What we're looking for (edit these to add/remove patterns)


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

# Output file name
OUTPUT_FILE = "deployed_legacy_api_findings.csv"


# extract_all_strings - Recursively dig through a JSON object and pull out every string value
# Logic App workflow definitions are deeply nested JSON - a URL might be buried inside
# something like $.definition.actions.HTTP_Call.inputs.uri
# We check if it's a dict (loop through keys), a list (loop through items), or a string (save it)
# Returns a list of tuples: [(path, string_value), ...]
def extract_all_strings(obj, path="$"):
    results = []
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = path + "." + key
            results.extend(extract_all_strings(value, new_path))
    
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            new_path = path + "[" + str(i) + "]"
            results.extend(extract_all_strings(value, new_path))
    
    elif isinstance(obj, str):
        results.append((path, obj))
    
    return results


# scan_definition - Take a Logic App workflow definition and scan it for legacy API patterns
# First extracts all strings from the nested JSON, then checks each one against our patterns
# Returns a list of findings (what was found and where)
def scan_definition(definition):
    findings = []
    all_strings = extract_all_strings(definition)
    
    for json_path, string_value in all_strings:
        
        for base in LEGACY_BASES:
            if base in string_value:
                findings.append({
                    "match_type": "legacy_base",
                    "matched": base,
                    "location": json_path
                })
        
        for connector in LEGACY_CONNECTORS:
            if connector in string_value:
                findings.append({
                    "match_type": "legacy_connector",
                    "matched": connector,
                    "location": json_path
                })
        
        for pattern in LEGACY_ENDPOINT_PATTERNS:
            if re.search(pattern, string_value, flags=re.IGNORECASE):
                findings.append({
                    "match_type": "legacy_endpoint",
                    "matched": pattern,
                    "location": json_path
                })
    
    # Remove duplicates
    unique = {}
    for f in findings:
        key = (f["match_type"], f["matched"], f["location"])
        unique[key] = f
    
    return list(unique.values())


# get_workflow_definition - Fetch the workflow definition JSON from a Logic App
# Logic Apps store their "definition" inside the resource properties
# The definition contains all the triggers, actions, and connections
# We use the ARM API to get this (api_version 2019-05-01 is for Logic Apps)
def get_workflow_definition(client, resource_id):
    api_version = "2019-05-01"
    
    try:
        # Use ARM API to get the full resource details (like clicking on it in Azure Portal)
        resource = client.resources.get_by_id(resource_id, api_version=api_version)
        properties = getattr(resource, "properties", None)
        
        if not properties:
            return None
        
        # The definition is inside properties - try different ways to get it
        # (Azure SDK sometimes returns dict, sometimes an object)
        if isinstance(properties, dict):
            return properties.get("definition")
        
        definition = getattr(properties, "definition", None)
        if definition:
            return definition
        
        # Try converting to dict
        try:
            return properties.as_dict().get("definition")
        except:
            return None
    
    except Exception as e:
        print("    Could not get definition: " + str(e)[:50])
        return None


# get_resource_group - Extract the resource group name from a full Azure resource ID
# Resource IDs look like: /subscriptions/xxx/resourceGroups/MY_RG/providers/Microsoft.Logic/workflows/MyApp
# We split by "/" and find what comes after "resourceGroups"
def get_resource_group(resource_id):
    parts = resource_id.split("/")
    if "resourceGroups" in parts:
        idx = parts.index("resourceGroups")
        return parts[idx + 1]
    return ""


# main - Entry point of the script
# 1. Ask for subscription ID
# 2. Connect to Azure using DefaultAzureCredential (picks up your az login)
# 3. List all resources and filter for Logic Apps (microsoft.logic/workflows)
# 4. For each Logic App, get its definition and scan for legacy APIs
# 5. Write results to CSV
def main():
    print("")
    print("=" * 60)
    print("LEGACY API SCANNER - Deployed Logic Apps")
    print("Find deprecated MDE/XDR APIs in live Azure playbooks")
    print("=" * 60)
    print("")
    print("NOTE: Make sure you ran 'az login' first!")
    print("")
    
    # Ask for subscription ID
    subscription_id = input("Enter your Azure Subscription ID: ").strip()
    
    if not subscription_id:
        print("ERROR: Subscription ID is required.")
        return
    
    print("")
    print("Connecting to Azure...")
    
    # DefaultAzureCredential automatically picks up your az login credentials
    # No need for client IDs, secrets, or app registrations - it just works!
    credential = DefaultAzureCredential()
    
    # ResourceManagementClient talks to Azure Resource Manager (ARM)
    # This is the same API that Azure Portal uses to list and manage resources
    client = ResourceManagementClient(credential, subscription_id)
    
    print("Connected!")
    print("")
    print("Listing Logic Apps...")
    print("")
    
    # These will track our results
    all_findings = []
    logic_apps_count = 0
    affected_count = 0
    
    # List ALL resources in the subscription
    # We'll filter for Logic Apps (type = microsoft.logic/workflows)
    resources = client.resources.list()
    
    for resource in resources:
        resource_type = getattr(resource, "type", "")
        
        # Check if this resource is a Logic App
        # Sentinel playbooks are Logic Apps with type "microsoft.logic/workflows"
        if resource_type.lower() == "microsoft.logic/workflows":
            logic_apps_count = logic_apps_count + 1
            print("Scanning: " + resource.name)
            
            # Get the resource group name from the resource ID
            resource_group = get_resource_group(resource.id)
            
            # Fetch the workflow definition (the JSON that describes the Logic App)
            definition = get_workflow_definition(client, resource.id)
            
            if not definition:
                print("    Skipped (no definition found)")
                continue
            
            # Scan the definition for legacy API patterns
            matches = scan_definition(definition)
            
            if matches:
                affected_count = affected_count + 1
                print("    FOUND " + str(len(matches)) + " legacy API matches!")
                
                # Add each match to our findings
                for m in matches:
                    all_findings.append({
                        "subscription": subscription_id,
                        "resource_group": resource_group,
                        "logic_app": resource.name,
                        "resource_id": resource.id,
                        "match_type": m["match_type"],
                        "matched": m["matched"],
                        "location": m["location"],
                    })
            else:
                print("    OK (no legacy APIs)")
    
    # Write all findings to CSV
    columns = ["subscription", "resource_group", "logic_app", "resource_id", 
               "match_type", "matched", "location"]
    
    all_findings.sort(key=lambda x: (x["resource_group"], x["logic_app"], x["match_type"]))
    
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for finding in all_findings:
            writer.writerow(finding)
    
    # Print summary
    print("")
    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print("")
    print("Logic Apps scanned: " + str(logic_apps_count))
    print("Logic Apps with legacy APIs: " + str(affected_count))
    print("Total matches found: " + str(len(all_findings)))
    print("Results saved to: " + OUTPUT_FILE)
    print("")
    
    # List affected Logic Apps
    if all_findings:
        affected = set()
        for f in all_findings:
            affected.add(f["logic_app"])
        
        print("Affected Logic Apps:")
        for name in sorted(affected):
            print("  - " + name)


if __name__ == "__main__":
    main()
