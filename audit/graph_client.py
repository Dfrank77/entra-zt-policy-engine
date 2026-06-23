"""
graph_client.py
Authenticates to Microsoft Graph via Azure CLI (DefaultAzureCredential)
and retrieves Conditional Access policies, named locations, and
authentication strength policies from the target tenant.
"""

import sys
import requests
from azure.identity import AzureCliCredential

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def get_headers():
    """Get auth headers using Azure CLI credential."""
    try:
        credential = AzureCliCredential()
        token = credential.get_token("https://graph.microsoft.com/.default")
        return {"Authorization": f"Bearer {token.token}"}
    except Exception as e:
        print(f"[ERROR] Authentication failed: {e}")
        print("Make sure you are logged in with: az login")
        sys.exit(1)


def list_conditional_access_policies(headers):
    """Retrieve all Conditional Access policies from the tenant."""
    response = requests.get(f"{GRAPH_BASE}/identity/conditionalAccess/policies", headers=headers)
    if response.status_code != 200:
        print(f"[ERROR] Failed to retrieve CA policies: {response.status_code}")
        print(response.text)
        return []
    return response.json().get("value", [])


def list_named_locations(headers):
    """Retrieve all named locations (IP ranges, countries)."""
    response = requests.get(f"{GRAPH_BASE}/identity/conditionalAccess/namedLocations", headers=headers)
    if response.status_code != 200:
        print(f"[ERROR] Failed to retrieve named locations: {response.status_code}")
        print(response.text)
        return []
    return response.json().get("value", [])


def list_authentication_strengths(headers):
    """Retrieve authentication strength policies."""
    response = requests.get(
        f"{GRAPH_BASE}/identity/conditionalAccess/authenticationStrength/policies",
        headers=headers,
    )
    if response.status_code != 200:
        print(f"[ERROR] Failed to retrieve auth strengths: {response.status_code}")
        print(response.text)
        return []
    return response.json().get("value", [])


if __name__ == "__main__":
    headers = get_headers()

    print("\n--- Conditional Access Policies ---")
    policies = list_conditional_access_policies(headers)
    for p in policies:
        print(f"  [{p.get('state', 'unknown')}] {p.get('displayName', 'Unnamed')}")
    print(f"\n  Total: {len(policies)} policies\n")

    print("--- Named Locations ---")
    locations = list_named_locations(headers)
    for loc in locations:
        print(f"  {loc.get('displayName', 'Unnamed')} ({loc.get('@odata.type', 'unknown')})")
    print(f"\n  Total: {len(locations)} locations\n")

    print("--- Authentication Strength Policies ---")
    strengths = list_authentication_strengths(headers)
    for s in strengths:
        print(f"  {s.get('displayName', 'Unnamed')}")
    print(f"\n  Total: {len(strengths)} policies\n")
