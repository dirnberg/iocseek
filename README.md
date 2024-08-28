
# iocseek

**iocseek** is a Dockerized tool designed for efficiently scanning files for Indicators of Compromise (IoCs), with a special focus on Industrial Control Systems (ICS). It identifies potential threats based on IP addresses, MAC addresses, MITRE techniques, and more, and outputs detailed results in YAML format.

## Features

- **Multi-File Support**: Scans `.rules`, `.json`, `.yml`, `.yara`, and `.md` files.
- **Customizable**: Configurable via a simple YAML file.
- **Dockerized**: Easy to deploy in any environment with Docker.
- **Detailed Logging**: Includes colored logging for clear and concise output.

## Installation

### Docker

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/iocseek.git
    cd iocseek
    ```

2. **Build the Docker image**:
    ```bash
    docker build -t iocseek .
    ```

## Usage

### Running the Docker Container

1. **Prepare your input files**:
   - Ensure you have the archive file (e.g., `example_archive.zip`) and a YAML configuration file (`config.yaml`).

2. **Run the Docker container**:
    ```bash
    docker run -v /path/to/input:/app/input -v /path/to/output:/app/output iocseek /app/input/example_archive.zip /app/input/config.yaml /app/output/results.yaml
    ```

   - Replace `/path/to/input` with the path to your input directory containing the archive and configuration files.
   - Replace `/path/to/output` with the path to your output directory where the results will be saved.

### Example YAML Configuration

Here is an example `config.yaml`:

```yaml
patterns:
  ip_regex: '([0-9]{1,3}\.){3}[0-9]{1,3}'
  mac_regex: '([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
  mitre_regex: 'T[0-9]{4}(\.[0-9]{3})?'  
  url_regex: '(https?:\/\/)?([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,6}(\/[a-zA-Z0-9\-\._\?\,'\/\\+&amp;%\$#\=~]*)?'
  domain_regex: '([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,6}'
  md5_regex: '[a-fA-F0-9]{32}'

lists:
  ip_list:
    - 192.168.1.1
    - 10.0.0.1
  mac_list:
    - 00:1A:2B:3C:4D:5E
  mitre_list:
    - T0845
  domain_list:
    - maliciousdomain.com
  url_list:
    - http://maliciousdomain.com/phishing
  protocol_list:
    - modbus
  md5_list:
    - 5d41402abc4b2a76b9719d911017c592

logging:
  level: INFO
  format: '%(asctime)s - %(levelname)s - %(message)s'
  output_file: 'script.log'
```

### Logs

Logs are configured via the `config.yaml` file. You can customize the log level, format, and specify an output file for the logs.

## Acknowledgment

This project was developed with assistance from ChatGPT-4 by OpenAI.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
