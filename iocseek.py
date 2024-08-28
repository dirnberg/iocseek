import os
import re
import yaml
import zipfile
import argparse
import logging
import coloredlogs
from collections import defaultdict

def load_yaml_config(yaml_path):
    with open(yaml_path, 'r') as file:
        return yaml.safe_load(file)

def configure_logging(logging_config):
    level = getattr(logging, logging_config.get('level', 'INFO').upper())
    format = logging_config.get('format', '%(asctime)s - %(levelname)s - %(message)s')
    output_file = logging_config.get('output_file', None)
    
    logging.basicConfig(level=level, format=format, filename=output_file)
    coloredlogs.install(level=level, fmt=format)
    logging.info("Logging configured.")

def search_iocs_in_file(filepath, ioc_lists, patterns):
    matches = defaultdict(list)
    with open(filepath, 'r', encoding='utf-8') as file):
        content = file.read()
        for ioc_type, ioc_list in ioc_lists.items():
            regex = patterns.get(ioc_type)
            matches[ioc_type].extend([ioc for ioc in ioc_list if regex and re.search(regex, ioc) and re.search(ioc, content)])
    return matches

def traverse_and_search(directory, ioc_lists, patterns, file_extensions):
    total_found = defaultdict(int)
    detailed_report = defaultdict(list)
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(tuple(file_extensions)):
                filepath = os.path.join(root, file)
                found_iocs = search_iocs_in_file(filepath, ioc_lists, patterns)
                for ioc_type, iocs in found_iocs.items():
                    total_found[ioc_type] += len(iocs)
                    detailed_report[ioc_type].extend(iocs)
    return total_found, detailed_report

def uncompress_zip(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    logging.info(f"Uncompressed {zip_path} to {extract_to}")

def save_results_to_yaml(output_path, total_found, ioc_lists, detailed_report):
    results = {
        "summary_report": {ioc_type: {"found": found_count, "total": len(ioc_lists[ioc_type]), "percentage": round((found_count / len(ioc_lists[ioc_type])) * 100, 2)} for ioc_type, found_count in total_found.items()},
        "detailed_report": {ioc_type: {"found": detailed_report[ioc_type], "not_found": list(set(ioc_lists[ioc_type]) - set(detailed_report[ioc_type]))} for ioc_type in ioc_lists}
    }
    with open(output_path, 'w') as file:
        yaml.dump(results, file)
    logging.info(f"Results saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Search for IoCs in compressed archive.")
    parser.add_argument("zip_path", help="Path to the compressed ZIP file.")
    parser.add_argument("yaml_path", help="Path to the YAML configuration file.")
    parser.add_argument("output_path", help="Path to save the result YAML file.")
    args = parser.parse_args()

    config = load_yaml_config(args.yaml_path)
    configure_logging(config.get('logging', {}))
    
    logging.info("Starting IoC search process...")
    
    patterns = config['patterns']
    ioc_lists = config['lists']
    file_extensions = ['.rules', '.json', '.yml', '.yara', '.md']
    
    extract_to = '/app/extracted_files'  # Path inside the container
    uncompress_zip(args.zip_path, extract_to)
    
    total_found, detailed_report = traverse_and_search(extract_to, ioc_lists, patterns, file_extensions)
    save_results_to_yaml(args.output_path, total_found, ioc_lists, detailed_report)
    
    logging.info("IoC search process completed.")

if __name__ == "__main__":
    main()
