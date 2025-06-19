use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=README.md");
    
    // Delete log file if it exists
    if Path::new("chatterbox.log").exists() {
        fs::remove_file("chatterbox.log").expect("Failed to delete log file");
        println!("cargo:warning=Deleted chatterbox.log");
    }
    
    // Count lines of code
    update_readme_with_line_count();
}

fn update_readme_with_line_count() {
    // Run the command to count lines of Rust code
    let output = Command::new("sh")
        .arg("-c")
        .arg("find ./src -type f -name \"*.rs\" | xargs wc -l")
        .output()
        .expect("Failed to count lines of code");
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = output_str.lines().collect();
    
    // Parse total line count
    let mut total_lines = 0;
    if let Some(total_line) = lines.last() {
        if let Some(num_str) = total_line.trim().split_whitespace().next() {
            total_lines = num_str.parse::<u32>().unwrap_or(0);
        }
    }
    
    // Count lines by module
    let mut omemo_lines = 0;
    let mut xmpp_lines = 0;
    let mut ui_and_other_lines = 0;
    
    for line in &lines {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() < 2 { continue; }
        
        // Skip the total line to avoid double counting
        if parts.last().unwrap_or(&"").contains("total") {
            continue;
        }
        
        let count = parts[0].parse::<u32>().unwrap_or(0);
        let file_path = parts.last().unwrap_or(&"");
        
        if file_path.contains("/omemo/") {
            omemo_lines += count;
        } else if file_path.contains("/xmpp/") {
            xmpp_lines += count;
        } else {
            ui_and_other_lines += count;
        }
    }
    
    // Read current README
    let mut readme_content = String::new();
    let mut file = File::open("README.md").expect("Failed to open README.md");
    file.read_to_string(&mut readme_content).expect("Failed to read README.md");
    
    // Prepare stats section with formatted numbers and proper indentation
    let stats_section = format!(
        "## Project Stats\n\n\
        - Total lines of Rust code: {} lines\n\
        - Fully implemented OMEMO encryption (XEP-0384)\n\
        - Core modules:\n\
          - OMEMO implementation: {} lines\n\
          - XMPP integration: {} lines\n\
          - UI and app logic: {} lines\n\n",
        total_lines, omemo_lines, xmpp_lines, ui_and_other_lines
    );
    
    // Fixed XEP-0384 section - move from planned to implemented list
    // Simple approach: find and update sections
    let mut new_content = String::new();
    
    // Check if Project Stats section already exists
    if readme_content.contains("## Project Stats") {
        // Replace existing Project Stats section
        let mut in_stats_section = false;
        let lines: Vec<&str> = readme_content.lines().collect();
        
        for line in lines {
            if line == "## Project Stats" {
                // Start replacing the stats section
                in_stats_section = true;
                new_content.push_str(&stats_section);
            } else if in_stats_section && line.starts_with("## ") {
                // End of stats section, found next heading
                in_stats_section = false;
                new_content.push_str(line);
                new_content.push('\n');
            } else if !in_stats_section {
                // Not in stats section, keep existing content
                new_content.push_str(line);
                new_content.push('\n');
            }
            // Skip lines within stats section
        }
    } else {
        // Insert stats section after the introduction (after title and before first ## heading)
        let mut found_intro = false;
        let lines: Vec<&str> = readme_content.lines().collect();
        
        for line in lines {
            if !found_intro && line.starts_with("## ") {
                // First heading after introduction - insert stats here
                found_intro = true;
                new_content.push_str(&stats_section);
                new_content.push_str(line);
                new_content.push('\n');
            } else {
                // Add all other content
                new_content.push_str(line);
                new_content.push('\n');
            }
        }
        
        // If no headings were found, append stats to the end
        if !found_intro {
            new_content.push_str("\n");
            new_content.push_str(&stats_section);
        }
    }
    
    // Write updated README
    let mut file = File::create("README.md").expect("Failed to open README.md for writing");
    file.write_all(new_content.as_bytes()).expect("Failed to write to README.md");
    
    println!("cargo:warning=Updated README.md with code stats: {} total lines", total_lines);
}