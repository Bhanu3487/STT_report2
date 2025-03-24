import os
import json
import pandas as pd

# Define paths
REPOSITORIES = ['pwntools', 'hosts', 'ArchieveBox']
OUTPUT_FOLDER = 'individual_repository_level_analysis'
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def parse_bandit_report(report_path):
    """
    Parses a single Bandit report JSON file and extracts security issue details.
    """
    with open(report_path, 'r') as f:
        report = json.load(f)

    high_conf, med_conf, low_conf = 0, 0, 0
    high_sev, med_sev, low_sev = 0, 0, 0
    unique_cwes = set()

    for result in report.get('results', []):
        confidence = result.get('issue_confidence', '').upper()
        severity = result.get('issue_severity', '').upper()
        cwe_id = result.get('issue_cwe', {}).get('id')

        # Count confidence levels
        if confidence == 'HIGH':
            high_conf += 1
        elif confidence == 'MEDIUM':
            med_conf += 1
        elif confidence == 'LOW':
            low_conf += 1

        # Count severity levels
        if severity == 'HIGH':
            high_sev += 1
        elif severity == 'MEDIUM':
            med_sev += 1
        elif severity == 'LOW':
            low_sev += 1

        # Collect unique CWE IDs
        if cwe_id:
            unique_cwes.add(cwe_id)

    return {
        'high_conf': high_conf,
        'med_conf': med_conf,
        'low_conf': low_conf,
        'high_sev': high_sev,
        'med_sev': med_sev,
        'low_sev': low_sev,
        'unique_cwes': list(unique_cwes),
        'total_unique_cwes': len(unique_cwes)
    }

def analyze_repository(repo_name):
    """
    Processes all Bandit reports for a given repository and generates a summary CSV.
    """
    print(f"Processing repository: {repo_name}...")
    
    reports_path = os.path.join(repo_name, 'bandit_reports')
    if not os.path.exists(reports_path):
        print(f"No Bandit reports found for {repo_name}, skipping.")
        return

    analysis_results = []
    
    for report_file in sorted(os.listdir(reports_path)):  # Sorting for chronological order
        report_path = os.path.join(reports_path, report_file)
        commit_hash = report_file.replace('.json', '')
        
        report_data = parse_bandit_report(report_path)
        report_data['repo'] = repo_name
        report_data['commit'] = commit_hash

        analysis_results.append(report_data)

    if not analysis_results:
        print(f"No valid Bandit reports processed for {repo_name}.")
        return

    df = pd.DataFrame(analysis_results)

    # Save to CSV
    output_file = os.path.join(OUTPUT_FOLDER, f'{repo_name}_bandit_summary.csv')
    df.to_csv(output_file, index=False)
    print(f"Analysis complete for {repo_name}. Summary saved to {output_file}")

# Execute analysis for each repository
for repo in REPOSITORIES:
    analyze_repository(repo)

print("All repositories analyzed. CSV summaries saved in the 'individual_repository_analysis' folder.")
