# iocseek

**iocseek** is a Dockerized tool designed for efficiently scanning files for Indicators of Compromise (IoCs), with a special focus on Industrial Control Systems (ICS). It identifies potential threats based on IP addresses, MAC addresses, MITRE techniques, and more, and outputs detailed results in YAML format.

## Features

- **Multi-File Support**: Scans `.rules`, `.json`, `.yml`, `.yara`, and `.md` files.
- **Customizable**: Configurable via a simple YAML file.
- **Dockerized**: Easy to deploy in any environment with Docker.
- **Detailed Logging**: Includes colored logging for clear and concise output.

## Requirements

- **Docker Version**: It is recommended to use Docker version 20.10 or later to ensure compatibility with the latest features and stability improvements.

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

#### On macOS and Linux

1. **Prepare your input files**:
   - Ensure you have the archive file (e.g., `example_archive.zip`) and a YAML configuration file (`config.yaml`).

2. **Run the Docker container**:
    ```bash
    docker run -v $(pwd)/input:/app/input -v $(pwd)/output:/app/output iocseek /app/input/example_archive.zip /app/input/config.yaml /app/output/results.yaml
    ```

   - Replace `$(pwd)/input` with the path to your input directory containing the archive and configuration files.
   - Replace `$(pwd)/output` with the path to your output directory where the results will be saved.

#### On Windows

1. **Prepare your input files**:
   - Ensure you have the archive file (e.g., `example_archive.zip`) and a YAML configuration file (`config.yaml`).

2. **Run the Docker container**:
    ```powershell
    docker run -v ${PWD}/input:/app/input -v ${PWD}/output:/app/output iocseek /app/input/example_archive.zip /app/input/config.yaml /app/output/results.yaml
    ```

   - Replace `${PWD}/input` with the path to your input directory containing the archive and configuration files.
   - Replace `${PWD}/output` with the path to your output directory where the results will be saved.

### Example YAML Configuration

Here is an example `config.yaml`:

```yaml
patterns:
  ip_regex: '([0-9]{1,3}\.){3}[0-9]{1,3}'
  mac_regex: '([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
  mitre_regex: 'T[0-9]{4}(\.[0-9]{3})?'  
  url_regex: '(https?:\/\/)?([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,6}(\/[a-zA-Z0-9\-\._\?\,\'\/\\\+&amp;%\$#\=~]*)?'
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

### Logs
Logs are configured via the config.yaml file. You can customize the log level, format, and specify an output file for the logs.

### Acknowledgment
This project was developed with assistance from ChatGPT-4 by OpenAI.

### Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

### License
This project is licensed under the MIT License - see the LICENSE file for details.

### Summary of Changes:

1. **Docker Version Recommendation**: Added a recommendation to use Docker version 20.10 or later.
2. **Usage Instructions**: Provided separate instructions for running Docker commands on macOS/Linux and Windows, accounting for differences in how file paths are handled across operating systems.
3. **Windows Command**: Modified the Docker run command to use `${PWD}` which is compatible with PowerShell, typically used on Windows.

This ensures users can correctly run the Docker container on different platforms and with the appropriate Docker version.


