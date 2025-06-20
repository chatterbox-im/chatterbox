use anyhow::Result;
use std::io::Write;
use log::{LevelFilter, Record};
use std::fs::OpenOptions;
use chrono::{DateTime, Local};

// This file contains utility functions that assist with various tasks in the application, such as formatting messages and handling errors.

pub struct SimpleLogger {
    log_file: Option<std::fs::File>,
}

impl SimpleLogger {
    pub fn new(log_file_path: Option<&str>) -> Result<Self> {
        let log_file = if let Some(path) = log_file_path {
            Some(OpenOptions::new().create(true).append(true).open(path)?)
        } else {
            None
        };

        Ok(SimpleLogger { log_file })
    }
}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now: DateTime<Local> = Local::now();
            // Enhanced logging format to include source file and line number for better debugging
            let log_message = format!(
                "[{}] {} [{}:{}] {}\n", 
                now.format("%Y-%m-%d %H:%M:%S"), 
                record.level(), 
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            );

            if let Some(file) = &self.log_file {
                let mut file = file.try_clone().unwrap();
                let _ = file.write_all(log_message.as_bytes());
            } else {
                // Only print to stdout if no log file is specified
                print!("{}", log_message);
            }
        }
    }

    fn flush(&self) {
        if let Some(file) = &self.log_file {
            let mut file = file.try_clone().unwrap();
            let _ = file.flush();
        } else {
            // Only flush stdout if no log file is specified
            let _: Result<(), std::io::Error> = std::io::stdout().flush();
        }
    }
}


/// Read a line of input from stdin, trimming whitespace
pub fn read_line() -> Result<String> {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub fn setup_logging(log_file: Option<&str>, level: LevelFilter) -> Result<()> {
    let logger = SimpleLogger::new(log_file)?;
    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(level))?;
    
    // Log startup information
    log::info!("Logging initialized at level: {}", level);
    log::info!("App version: {} (built on {})", env!("CARGO_PKG_VERSION", "unknown"), env!("CARGO_PKG_NAME", "chatterbox"));
    
    Ok(())
}