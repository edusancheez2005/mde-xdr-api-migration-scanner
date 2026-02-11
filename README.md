# Legacy API Scanner

Find deprecated MDE/XDR APIs in Sentinel playbooks.

## Scripts

| Script | What It Does |
`scan_templates.py` | Scan local folders OR GitHub repos directly 
`scan_deployed.py` | Scan live Logic Apps in Azure 

## What Gets Detected

**Old API URLs:**
- `api.securitycenter.microsoft.com` (old MDE)
- `api.security.microsoft.com` (old XDR)

**Old connectors:**
- `MicrosoftDefenderATP`
- `shared_windowsdefenderatp`

**Old API paths:** (you can add more in the script)
- `/api/machines/{id}/isolate`, `/unisolate`, `/runAntiVirusScan`, `/offboard`
- `/api/vulnerabilities`, `/api/exposureScore`
- `/api/alerts`, `/api/incidents`
- `/api/advancedqueries/run`

---

## Script 1: Scan Templates

Scans for legacy APIs in playbook template files.

### Requirements

```powershell
pip install requests
```

(Only needed if scanning GitHub repos directly)

### How to Use

```powershell
python scan_templates.py
```

It will ask you for input. You can enter:
- **A local folder path:** `C:\repos\Azure-Sentinel`
- **A GitHub URL:** `https://github.com/Azure/Azure-Sentinel`

### GitHub Token (required for private repos)

If scanning a GitHub repo, you need a Personal Access Token:

1. Go to: https://github.com/settings/tokens
2. Click **Generate new token** > **Generate new token (classic)**
3. Give it a name like "API Scanner"
4. Select scope: **repo** (full control of private repositories)
5. Click **Generate token**
6. Copy the token and paste it when the script asks

### Output

`legacy_api_findings.csv` with columns: file, path, match type, matched and location

---

## Script 2: Scan Deployed Logic Apps

Scans live Logic Apps in your Azure subscription.

### Requirements

powershell
pip install azure-identity azure-mgmt-resource


### How to Use

powershell
az login - for logging into Azure
python scan_deployed.py


It will ask you for your subscription ID.

### How to Find Your Subscription ID

powershell
az account show --query id --output tsv


### Output

`deployed_legacy_api_findings.csv` with columns: subscription id, resource group, logic app, resource id, match type, matched, and location

---

## Troubleshooting

**Folder not found:** Check the path is correct

**GitHub scan fails:** Run `pip install requests` first

**DefaultAzureCredential failed:** Run `az login` first

**Access Denied:** You need Reader access to the subscription
