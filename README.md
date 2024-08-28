# IoCSeek

`IoCSeek` is a tool designed to search for Indicators of Compromise (IoCs) across various files, especially those used in cybersecurity analysis. The tool scans files for specific IoCs such as IP addresses, MAC addresses, MITRE techniques, URLs, domains, and more.

## Features

- **Multi-File Support**: Can scan `.rules`, `.json`, `.yml`, `.yara`, and `.md` files.
- **Customizable**: Allows you to define search patterns and IoCs via a YAML configuration file.
- **Categorized Results**: The results are categorized, indicating which IoCs were found and which were not.
- **Points Calculation**: Displays the number of IoCs found relative to the defined IoCs for each category.

## Requirements

- **Rust**: Make sure you have the Rust toolchain installed. You can install it [here](https://www.rust-lang.org/tools/install).

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/yourusername/iocseek.git
    cd iocseek
    ```

2. Build the release version:

    ```bash
    cargo build --release
    ```

## Usage

### Running the Tool

```bash
./target/release/iocseek --config config/config.yml --input input_directory --output output/results.yml
```

- **config.yml**: The YAML file defining the IoCs to search for and the search patterns.
- **input_directory**: The directory containing the files to be scanned.
- **results.yml**: The file where the results will be saved.

### Example of `config.yml`

```yaml
patterns:
  ip_regex: "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"
  mac_regex: "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
  mitre_regex: "T[0-9]{4}(\\.[0-9]{3})?"
  url_regex: "https?://[^\\s/$.?#].[^\\s]*"
  domain_regex: "[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}"
  sha256_regex: "[a-fA-F0-9]{64}"

lists:
  ip_list:
    - "192.168.1.1"
    - "10.0.0.1"
  mac_list:
    - "00:0a:95:9d:68:16"
    - "00:14:22:01:23:45"
  mitre_list:
    - "T1078"
    - "T1190"
  domain_list:
    - "example.com"
    - "maliciousdomain.com"
  url_list:
    - "http://example.com/malicious"
    - "https://phishing-site.com/login"
  protocol_list:
    - "modbus"
    - "s7comm"
    - "iec104"
  sha256_list:
    - "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

### Understanding the Results

The results are saved in the `results.yml` file and include:

- **Found IoCs**: A list of IoCs that were found in the files.
- **Not Found IoCs**: A list of IoCs that were not found in the files.
- **Points Per Category**: The number of IoCs found relative to the number of defined IoCs for each category.
- **Total Points**: The total number of IoCs found relative to the maximum possible points.

### Example Output

```yaml
found:
  IP Addresses:
    - "192.168.1.1"
  MAC Addresses:
    - "00:0a:95:9d:68:16"
  URLs:
    - "https://phishing-site.com/login"
  SHA-256 Hashes:
    - "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
notfound:
  Domains: []
  MITRE Techniques: []
  Protocols: []
summary:
  IP Addresses: 1
  MAC Addresses: 1
  MITRE Techniques: 0
  URLs: 1
  Domains: 0
  SHA-256 Hashes: 1
  Protocols: 0
points_per_category:
  IP Addresses: "1/2"
  MAC Addresses: "1/2"
  MITRE Techniques: "0/2"
  URLs: "1/2"
  Domains: "0/2"
  SHA-256 Hashes: "1/1"
  Protocols: "0/3"
total_points: "4/12"
```

## Development

Want to contribute to the project? Fork the repository and submit a pull request. Bug reports and feature requests are welcome!

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
