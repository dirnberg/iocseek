#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn test_iocseek() {
        // Create a sample config.yml
        let config_content = r#"
        patterns:
          ip_regex: "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"
          mac_regex: "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
          mitre_regex: "T[0-9]{4}(\\.[0-9]{3})?"
          url_regex: "https?://[^\\s/$.?#].[^\\s]*"
          domain_regex: "[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}"
          sha256_regex: "[a-fA-F0-9]{64}"
          sha512_regex: "[a-fA-F0-9]{128}"
        lists:
          ip_list:
            - "192.168.1.1"
            - "10.0.0.1"
            - "192.168.1.2" # Extra to test max count
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
          sha512_list:
            - "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d8db5afedeb533dd14f17224850b28f0e6a1d5f6dcef15b9f70951f"
        "#;

        let config_path = "test_config.yml";
        let mut config_file = File::create(config_path).unwrap();
        config_file.write_all(config_content.as_bytes()).unwrap();

        // Create a sample input directory and file
        let input_dir = "test_input";
        let input_file_path = Path::new(input_dir).join("sample.txt");
        fs::create_dir_all(input_dir).unwrap();
        let mut input_file = File::create(&input_file_path).unwrap();
        input_file.write_all(b"192.168.1.1 is the IP address. 00:0a:95:9d:68:16 is a MAC address. https://phishing-site.com/login and a SHA-256 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and a SHA-512 hash cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d8db5afedeb533dd14f17224850b28f0e6a1d5f6dcef15b9f70951f").unwrap();

        // Define the output path
        let output_path = "test_output.yml";

        // Load the config and run the program
        let config = load_config(config_path).unwrap();
        let total_matches = traverse_and_search(Path::new(input_dir), &config.patterns, &config.lists).unwrap();
        save_results_to_yaml(output_path, &total_matches, &config.lists).unwrap();

        // Verify the results
        let actual_output = std::fs::read_to_string(output_path).unwrap();

        // Check that all the IoCs are in the results as expected
        assert!(actual_output.contains("192.168.1.1"));
        assert!(actual_output.contains("00:0a:95:9d:68:16"));
        assert!(actual_output.contains("https://phishing-site.com/login"));
        assert!(actual_output.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert!(actual_output.contains("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d8db5afedeb533dd14f17224850b28f0e6a1d5f6dcef15b9f70951f"));

        // Ensure the points are calculated correctly, considering max limits
        assert!(actual_output.contains("IP Addresses: 1/3"));
        assert!(actual_output.contains("MAC Addresses: 1/2"));
        assert!(actual_output.contains("MITRE Techniques: 0/2")); // None of these IoCs are present
        assert!(actual_output.contains("URLs: 1/2"));
        assert!(actual_output.contains("Domains: 0/2")); // None of these IoCs are present
        assert!(actual_output.contains("SHA-256 Hashes: 1/1"));
        assert!(actual_output.contains("SHA-512 Hashes: 1/1"));
        assert!(actual_output.contains("Protocols: 0/3")); // None of these IoCs are present

        // Cleanup
        fs::remove_file(config_path).unwrap();
        fs::remove_file(output_path).unwrap();
        fs::remove_dir_all(input_dir).unwrap();
    }
}
