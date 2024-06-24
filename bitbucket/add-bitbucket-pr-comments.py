import json
import os
import sys
import requests
import argparse

# Check for required environment variables
BITBUCKET_REPO_OWNER = os.getenv('BITBUCKET_REPO_OWNER')
BITBUCKET_REPO_SLUG = os.getenv('BITBUCKET_REPO_SLUG')
BITBUCKET_COMMIT = os.getenv('BITBUCKET_COMMIT')

if not all([BITBUCKET_REPO_OWNER, BITBUCKET_REPO_SLUG, BITBUCKET_COMMIT]):
     sys.exit("Error: One or more required environment variables (BITBUCKET_REPO_OWNER, BITBUCKET_REPO_SLUG, BITBUCKET_COMMIT) are not set.")

#This is an internal proxy running in the BitBucket environment to accept Code Insights
proxies = {"http": "http://localhost:29418"}

def load_json_with_unescaped_characters(file_path):
    """Load and return JSON data from a file, replacing unescaped characters if necessary."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            json_str = file.read().strip()
        return json.loads(json_str)
    except json.decoder.JSONDecodeError as e:
        print(f"Failed to parse JSON: {e}")
        return None
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit()

def construct_report_payload(endor_findings):
    """Construct and return the payload for creating a Bitbucket report."""
    warning_findings_count = len(endor_findings.get('warning_findings', []))
    blocking_findings_count = len(endor_findings.get('blocking_findings', []))
    total_violations = warning_findings_count + blocking_findings_count
    result = "PASSED" if total_violations == 0 else "FAILED"
    report_payload = {
        "title": "Endor Labs Policy Violations",
        "details": f"Endor Labs detected {total_violations} policy violations associated with this pull request.\n\n{endor_findings['warnings'][0]}",
        "report_type": "SECURITY",
        "reporter": "Endor Labs",
        "link": f"https://app.endorlabs.com/t/{namespace}/projects/{project_uuid}/pr-runs/{report_id}",
        "logo_url": "https://avatars.githubusercontent.com/u/92199924",
        "result": result,
        "data": [
            {"title": "Warning Findings", "type": "NUMBER", "value": warning_findings_count},
            {"title": "Blocking Findings", "type": "NUMBER", "value": blocking_findings_count}
        ]
    }
    return report_payload

def construct_annotation_payload(finding):
    """Construct and return the payload for creating an annotation in Bitbucket."""
    title = "Endor Labs Policy Violation"
    summary = finding['meta']['description']
    details =  f"{finding['spec']['summary']}\n\n{finding['spec']['remediation']}"
    severity = "CRITICAL" if finding['spec']['level'] == "FINDING_LEVEL_CRITICAL" else \
               "HIGH" if finding['spec']['level'] == "FINDING_LEVEL_HIGH" else \
               "MEDIUM" if finding['spec']['level'] == "FINDING_LEVEL_MEDIUM" else "LOW"
    affected_paths = finding['spec'].get('dependency_file_paths', [])
    path = affected_paths[0] if affected_paths else "Unknown file"
    annotation_payload = {
        "external_id": finding['uuid'],
        "title": title,
        "annotation_type": "VULNERABILITY",
        "summary": summary,
        "details": details,
        "severity": severity,
        "path": path
    }
    return annotation_payload

def send_report(report_payload):
    """Send the constructed report payload to the Bitbucket API."""
    report_url = f"http://api.bitbucket.org/2.0/repositories/{BITBUCKET_REPO_OWNER}/{BITBUCKET_REPO_SLUG}/commit/{BITBUCKET_COMMIT}/reports/{report_id}"
    response = requests.put(report_url, json=report_payload, proxies=proxies)
    if response.status_code in [200, 201]:
        print("Report created or updated successfully")
    else:
        print(f"Failed to create or update report: {response.text}")

def send_annotation(annotation_payload):
    """Send the constructed annotation payload to the Bitbucket API."""
    annotation_url = f"{base_url}/{report_id}/annotations/{annotation_payload['external_id']}" 
    response = requests.put(annotation_url, json=annotation_payload, proxies=proxies)
    if response.status_code in [200, 201]:
        print("Annotation added successfully")
    else:
        print(f"Failed to add annotation: {response.text}")

def process_findings(filename):
    """Load findings from JSON, create a report, and add annotations for each finding."""
    endor_findings = load_json_with_unescaped_characters(filename)
    if endor_findings is None:
        print("Failed to load findings. Exiting.")
        return

    global report_id, project_uuid, namespace

    # Define the order of keys to check
    finding_types = ['all_findings', 'warning_findings', 'blocking_findings']

    # Iterate over finding types and extract the first one found
    for finding_type in finding_types:
        if endor_findings.get(finding_type):
            first_finding = endor_findings[finding_type][0]
            report_id = first_finding['context']['id']
            project_uuid = first_finding['spec']['project_uuid']
            namespace = first_finding['tenant_meta']['namespace']
            break  # Stop after finding the first non-empty list

    if not report_id:
        print("No findings found.")
        sys.exit()

    # Prepare the base URL for Bitbucket API requests
    global base_url
    base_url = f"http://api.bitbucket.org/2.0/repositories/{BITBUCKET_REPO_OWNER}/{BITBUCKET_REPO_SLUG}/commit/{BITBUCKET_COMMIT}/reports"

    # Create the report
    report_payload = construct_report_payload(endor_findings)
    send_report(report_payload)

    # Iterate over findings and create annotations
    for finding in endor_findings.get('blocking_findings', []) + endor_findings.get('warning_findings', []):
        annotation_payload = construct_annotation_payload(finding)
        send_annotation(annotation_payload)

def main():
    """Main function to parse arguments and process findings."""
    parser = argparse.ArgumentParser(description="Script to process findings and update Bitbucket via API.")
    parser.add_argument("filename", help="Filename containing the JSON findings.")
    args = parser.parse_args()

    process_findings(args.filename)

if __name__ == "__main__":
    main()
