"""Test TAXII 2.1 server push and poll round-trip."""

import sys
from taxii_client import TAXIIClient
from stix2 import Indicator

def main():
    print("[*] Initializing TAXII client targeting local server...")
    client = TAXIIClient("http://localhost:6100")
    
    # 1. Health check
    print("[*] Checking health...")
    if not client.is_server_alive():
        print("[!] TAXII server is not alive!")
        sys.exit(1)
    print("[+] TAXII server is alive.")

    # 2. List collections
    print("[*] Listing collections...")
    collections = client.list_collections()
    print(f"[+] Collections found: {[c['id'] for c in collections]}")

    # 3. Create a test indicator
    print("[*] Creating test STIX 2.1 indicator...")
    indicator = Indicator(
        name="Test Indicator",
        pattern="[url:value = 'http://example.com/malicious']",
        pattern_type="stix",
        labels=["test-threat"],
    )
    print(f"[+] Generated STIX Indicator: {indicator.id}")

    # 4. Push to urlhaus-indicators
    collection_id = "urlhaus-indicators"
    print(f"[*] Pushing indicator to collection '{collection_id}'...")
    push_res = client.push_objects(collection_id, [indicator])
    print(f"[+] Push result: {push_res}")

    # 5. Poll from urlhaus-indicators
    print(f"[*] Polling collection '{collection_id}'...")
    polled_objects = client.poll_objects(collection_id)
    print(f"[+] Polled {len(polled_objects)} objects total.")
    
    found = False
    for obj in polled_objects:
        if obj.get("id") == indicator.id:
            print(f"[+] Successfully found our indicator {obj['id']}!")
            print(f"    Name: {obj.get('name')}")
            print(f"    Pattern: {obj.get('pattern')}")
            found = True
            break
            
    if not found:
        print("[!] Pushed indicator was not found in the polled results!")
        sys.exit(1)
        
    print("[+] TAXII 2.1 push-poll round-trip test passed successfully!")

if __name__ == "__main__":
    main()
