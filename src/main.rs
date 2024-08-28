use clap::Parser; // Import the Parser trait from clap
use regex::Regex; // Regular expressions for pattern matching
use serde::{Deserialize, Serialize}; // Deserialize YAML configuration into Rust structs and Serialize results
use std::collections::{HashMap, HashSet}; // Data structures to store matches
use std::fs::{self, File}; // File operations
use std::io::Read; // Reading file contents
use std::path::Path; // Handling file paths
use std::process; // Exit the program with a status code
use std::error::Error; // Error handling

/// Command-line arguments structure
#[derive(Parser, Debug)]  // Derive the Parser trait for command-line parsing
struct Args {
    /// Path to the configuration file
    #[clap(short, long)]
    config: String,

    /// Path to the input directory (extracted files)
    #[clap(short, long)]
    input: String,

    /// Path to the output file for results
    #[clap(short, long)]
    output: String,
}

/// Structure for the overall configuration loaded from YAML
#[derive(Debug, Deserialize)]
struct Config {
    patterns: Patterns,
    lists: Lists,
}

/// Structure for the pattern matching configurations
#[derive(Debug, Deserialize)]
struct Patterns {
    ip_regex: String,
    mac_regex: String,
    mitre_regex: String,
    url_regex: String,
    domain_regex: String,
    sha256_regex: String,
}

/// Structure for the lists of IoCs to search for
#[derive(Debug, Deserialize)]
struct Lists {
    ip_list: Vec<String>,
    mac_list: Vec<String>,
    mitre_list: Vec<String>,
    domain_list: Vec<String>,
    url_list: Vec<String>,
    protocol_list: Vec<String>,
    sha256_list: Vec<String>,
}

/// Structure for saving the results, including a summary
#[derive(Debug, Serialize)]
struct Results {
    found: HashMap<String, Vec<String>>,
    notfound: HashMap<String, Vec<String>>,
    summary: HashMap<String, usize>,
    points_per_category: HashMap<String, String>,
    total_points: String,
}

/// Function to load and parse the YAML configuration file with validation
fn load_config(path: &str) -> Result<Config, Box<dyn Error>> {
    let file = File::open(path)?; // Open the YAML file
    let config: Config = serde_yaml::from_reader(file)?; // Parse YAML into Config struct
    Ok(config)
}

/// Function to search a file for Indicators of Compromise (IoCs) based on the patterns and lists
fn search_iocs_in_file(file_path: &Path, patterns: &Patterns, lists: &Lists) -> Result<HashMap<String, Vec<String>>, Box<dyn Error>> {
    let mut matches: HashMap<String, Vec<String>> = HashMap::new(); // Store the found matches
    let mut content = String::new(); // String to hold the file content

    // Open and read the file content
    File::open(file_path)?.read_to_string(&mut content)?;

    // Helper function to perform matching
    let mut match_and_insert = |regex: &Regex, list: &[String], key: &str| {
        let mut found_set = HashSet::new(); // To ensure uniqueness
        for item in list {
            if regex.is_match(item) && content.contains(item) && found_set.len() < list.len() {
                found_set.insert(item.clone());
            }
        }
        matches.entry(key.to_string()).or_default().extend(found_set.into_iter());
    };

    // Perform pattern matching
    match_and_insert(&Regex::new(&patterns.ip_regex)?, &lists.ip_list, "IP Addresses");
    match_and_insert(&Regex::new(&patterns.mac_regex)?, &lists.mac_list, "MAC Addresses");
    match_and_insert(&Regex::new(&patterns.mitre_regex)?, &lists.mitre_list, "MITRE Techniques");
    match_and_insert(&Regex::new(&patterns.url_regex)?, &lists.url_list, "URLs");
    match_and_insert(&Regex::new(&patterns.domain_regex)?, &lists.domain_list, "Domains");
    match_and_insert(&Regex::new(&patterns.sha256_regex)?, &lists.sha256_list, "SHA-256 Hashes");

    // Match industrial protocols directly (no regex needed)
    let mut found_protocols = HashSet::new();
    for protocol in &lists.protocol_list {
        if content.contains(protocol) && found_protocols.len() < lists.protocol_list.len() {
            found_protocols.insert(protocol.clone());
        }
    }
    matches.entry("Protocols".to_string()).or_default().extend(found_protocols.into_iter());

    Ok(matches)
}

/// Function to traverse a directory and search all files for IoCs
fn traverse_and_search(directory: &Path, patterns: &Patterns, lists: &Lists) -> Result<HashMap<String, Vec<String>>, Box<dyn Error>> {
    let mut total_matches: HashMap<String, Vec<String>> = HashMap::new(); // Store all matches

    // Iterate over each file in the directory
    for entry in fs::read_dir(directory)? {
        let entry = entry?; // Handle directory entry
        let path = entry.path(); // Get the file path

        if path.is_file() {
            // Search the file for IoCs
            let matches = search_iocs_in_file(&path, patterns, lists)?;
            // Merge the matches into the total matches
            for (key, value) in matches {
                total_matches.entry(key).or_default().extend(value);
            }
        }
    }

    // Ensure uniqueness in final results
    for value in total_matches.values_mut() {
        value.sort();
        value.dedup();
    }

    Ok(total_matches)
}

/// Function to save the results to a YAML file, including a summary, and print the results
fn save_results_to_yaml(path: &str, results: &HashMap<String, Vec<String>>, lists: &Lists) -> Result<(), Box<dyn Error>> {
    let file = File::create(path)?; // Create the output file

    // Calculate how many IoCs from each category were found
    let mut summary: HashMap<String, usize> = HashMap::new();
    let mut points_per_category: HashMap<String, String> = HashMap::new();
    let mut total_points: usize = 0;
    let mut max_points: usize = 0;

    // Prepare found and notfound sections
    let mut found: HashMap<String, Vec<String>> = HashMap::new();
    let mut notfound: HashMap<String, Vec<String>> = HashMap::new();

    // Helper function to calculate points and separate found/notfound items
    let mut calculate_points = |key: &str, list: &[String]| {
        let found_items: Vec<String> = list.iter().filter(|item| results.get(key).unwrap_or(&vec![]).contains(item)).cloned().collect();
        let notfound_items: Vec<String> = list.iter().filter(|item| !results.get(key).unwrap_or(&vec![]).contains(item)).cloned().collect();

        found.insert(key.to_string(), found_items.clone());
        notfound.insert(key.to_string(), notfound_items.clone());

        let points = found_items.len();
        let max = list.len();

        summary.insert(key.to_string(), points);
        points_per_category.insert(key.to_string(), format!("{}/{}", points, max));

        total_points += points;
        max_points += max;
    };

    // Calculate points for each category in the order of the configuration file
    let categories = [
        ("IP Addresses", &lists.ip_list),
        ("MAC Addresses", &lists.mac_list),
        ("MITRE Techniques", &lists.mitre_list),
        ("URLs", &lists.url_list),
        ("Domains", &lists.domain_list),
        ("SHA-256 Hashes", &lists.sha256_list),
        ("Protocols", &lists.protocol_list),
    ];

    for (category, list) in &categories {
        calculate_points(category, list);
    }

    // Output to the console in the sorted order
    println!("\n--- IoC Search Results ---");

    println!("\nTotal Points: {}/{}\n", total_points, max_points);

    let output = Results {
        found,
        notfound,
        summary,
        points_per_category,
        total_points: format!("{}/{}", total_points, max_points),
    };

    serde_yaml::to_writer(file, &output)?; // Write the results and summary to the file in YAML format
    Ok(())
}

/// Main function - entry point of the program
fn main() {
    // Parse command-line arguments
    let args = Args::parse();

    let config_path = &args.config; // Path to the config file
    let directory_to_search = &args.input; // Path to the input directory
    let result_output_path = &args.output; // Path to the output file

    // Load the configuration file
    let config = match load_config(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Failed to load config file: {}", err);
            process::exit(1);
        }
    };

    // Traverse the directory and search for IoCs
    let total_matches = match traverse_and_search(Path::new(directory_to_search), &config.patterns, &config.lists) {
        Ok(matches) => matches,
        Err(err) => {
            eprintln!("Error during search: {}", err);
            process::exit(1);
        }
    };

    // Save the results to a YAML file
    if let Err(err) = save_results_to_yaml(result_output_path, &total_matches, &config.lists) {
        eprintln!("Failed to save results: {}", err);
        process::exit(1);
    }

    println!("IoC search process completed successfully.");
}
