#![deny(dead_code)] // DO NOT REMOVE THIS EVER
use anyhow::Result;
use clap::Parser;
use log::{error, info, LevelFilter};
use std::path::PathBuf;
use std::{
    env,
    io::{self, Write},
};

mod app;
mod credentials;
mod ui;
mod utils;

use crate::credentials::{load_credentials, save_credentials, Credentials};
use chatterbox::xmpp::XMPPClient;

/// Command line arguments for Sermo
#[derive(Parser, Debug)]
#[command(
    author,
    version = concat!(env!("CARGO_PKG_VERSION"), " (#", env!("GIT_COMMIT_HASH"), ")"),
    about = "Chatterbox: A CLI XMPP chat client with OMEMO encryption.",
    long_about = "Chatterbox is a command-line chat client for XMPP with OMEMO encryption support.\n\n\
    Optional parameters:\n\
    --omemo-dir <PATH>     Override the directory for OMEMO device_id, identity_key, and multi-device info files\n\
    --disable-mam          Disable Message Archive Management (MAM) - no historical messages will be loaded\n\
    Use -h or --help to see all options."
)]
struct Args {
    /// Directory for OMEMO device_id, identity_key, and multi-device info files
    #[arg(
        long,
        value_name = "PATH",
        help = "Override the directory for OMEMO device_id, identity_key, and multi-device info files"
    )]
    omemo_dir: Option<PathBuf>,

    /// Disable Message Archive Management (MAM) - no historical messages will be loaded
    #[arg(
        long,
        help = "Disable Message Archive Management (MAM) - no historical messages will be loaded"
    )]
    disable_mam: bool,
}

/// Prompts the user for login credentials or uses environment variables
fn prompt_credentials() -> (String, String, String) {
    let server = env::var("XMPP_SERVER").unwrap_or_else(|_| {
        eprintln!("Enter XMPP server domain (e.g., example.com):");
        utils::read_line().unwrap_or_default().trim().to_string()
    });

    let username = env::var("XMPP_USERNAME").unwrap_or_else(|_| {
        eprintln!("Enter username (without domain part if using XMPP_SERVER):");
        utils::read_line().unwrap_or_default().trim().to_string()
    });

    let password = env::var("XMPP_PASSWORD").unwrap_or_else(|_| {
        eprintln!("Enter password (input will not be shown):");
        utils::read_line().unwrap_or_default()
    });

    (server, username, password)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments FIRST
    let args = Args::parse();

    // Determine the log file path based on --omemo-dir
    // In release builds, do not create a log file (avoid leaking sensitive data to disk)
    let log_file_path: Option<PathBuf> = if cfg!(debug_assertions) {
        Some(match &args.omemo_dir {
            Some(dir) => {
                // Ensure the directory exists, create it if not
                if !dir.exists() {
                    if let Err(e) = std::fs::create_dir_all(dir) {
                        eprintln!("Warning: Failed to create OMEMO directory {}: {}. Log file might not be created.", dir.display(), e);
                        PathBuf::from("chatterbox.log")
                    } else {
                        dir.join("chatterbox.log")
                    }
                } else {
                    dir.join("chatterbox.log")
                }
            }
            None => match dirs::data_dir() {
                Some(mut data_dir) => {
                    data_dir.push("chatterbox");
                    if let Err(e) = std::fs::create_dir_all(&data_dir) {
                        eprintln!("Warning: Failed to create log directory {}: {}. Falling back to current directory.", data_dir.display(), e);
                        PathBuf::from("chatterbox.log")
                    } else {
                        data_dir.join("chatterbox.log")
                    }
                }
                None => {
                    eprintln!("Warning: Could not determine XDG data directory. Falling back to current directory for logging.");
                    PathBuf::from("chatterbox.log")
                }
            },
        })
    } else {
        None
    };

    // Setup logging with the determined path
    // In release builds, disable logging entirely (no file, no stdout)
    let log_level = if cfg!(debug_assertions) {
        LevelFilter::Debug
    } else {
        LevelFilter::Off
    };
    utils::setup_logging(log_file_path.as_deref().and_then(|p| p.to_str()), log_level)?;

    info!("Chatterbox XMPP Chat client starting up");
    info!(
        "System information: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    if let Some(ref path) = log_file_path {
        info!("Logging to file: {}", path.display());
    }

    // Patch: Override OMEMO secrets directory if provided
    // This needs to happen AFTER logging setup but before client initialization
    if let Some(ref omemo_dir) = args.omemo_dir {
        // Ensure the override function can handle the directory possibly being created above
        chatterbox::omemo::device_id::set_omemo_dir_override(omemo_dir.clone());
        info!("OMEMO directory overridden to: {}", omemo_dir.display());
    }

    // Get credentials: prefer environment variables, then file, then prompt
    let (server, username, password, credentials_from_env) =
        if let (Ok(server), Ok(username), Ok(password)) = (
            env::var("XMPP_SERVER"),
            env::var("XMPP_USERNAME"),
            env::var("XMPP_PASSWORD"),
        ) {
            (server, username, password, true)
        } else if let Some(creds) = load_credentials()? {
            info!("Using cached credentials for {}", creds.username);
            if let Some(password) = creds.get_password() {
                (creds.server, creds.username, password, false)
            } else {
                eprintln!("Enter password for {}@{}:", creds.username, creds.server);
                let password = utils::read_line().unwrap_or_default();
                (creds.server, creds.username, password, false)
            }
        } else {
            let (server, username, password) = prompt_credentials();
            (server, username, password, false)
        };

    // Print initial connection message
    print!("Connecting to {}@{}... please wait", username, server);
    io::stdout().flush().unwrap();

    // Set up the XMPP client
    let (mut xmpp_client, msg_rx) = XMPPClient::new();

    // Set OMEMO JID for user-specific storage before OMEMO initialization
    let bare_jid = username.split('/').next().unwrap_or(&username);
    chatterbox::omemo::device_id::set_omemo_jid(bare_jid);

    // Start the animated dots task
    let (dots_stop_tx, mut dots_stop_rx) = tokio::sync::mpsc::channel(1);
    let username_clone = username.clone();
    let server_clone = server.clone();
    let dots_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
        let mut dots_count = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    print!(".");
                    io::stdout().flush().unwrap();
                    dots_count += 1;
                    // Reset line after 6 dots for better readability
                    if dots_count >= 6 {
                        print!("\rConnecting to {}@{}... please wait", username_clone, server_clone);
                        io::stdout().flush().unwrap();
                        dots_count = 0;
                    }
                }
                _ = dots_stop_rx.recv() => {
                    break;
                }
            }
        }
    });

    let connection_result = xmpp_client.connect(&server, &username, &password).await;

    // Stop the dots animation
    let _ = dots_stop_tx.send(()).await;
    dots_task.abort(); // Ensure the task is stopped

    // Clear the connection line and move to next line
    let connection_msg = format!("Connecting to {}@{}... please wait......", username, server);
    print!("\r{}\r", " ".repeat(connection_msg.len()));
    io::stdout().flush().unwrap();

    let typing_rx_holder;
    match connection_result {
        Ok(_) => {
            println!("Connected successfully!");

            // Save credentials on successful connection, but only if not from env vars
            if !credentials_from_env {
                let credentials = Credentials::new(&server, &username, &password);
                if let Err(e) = save_credentials(&credentials) {
                    eprintln!("Warning: Failed to save credentials: {}", e);
                }
            }

            // Initialize OMEMO encryption first
            info!("Initializing OMEMO encryption...");
            match xmpp_client.initialize_client().await {
                Ok(_) => {
                    info!("OMEMO encryption initialized successfully");
                }
                Err(e) => {
                    error!("Failed to initialize OMEMO encryption: {}. Continuing without E2E encryption.", e);
                    eprintln!("Warning: OMEMO encryption unavailable: {}", e);
                }
            }

            // Create typing notification channel and store in client BEFORE publishing state
            let (typing_tx, typing_rx_inner) =
                tokio::sync::mpsc::channel::<(String, chatterbox::xmpp::TypingStatus)>(100);
            xmpp_client.typing_tx = Some(typing_tx);
            typing_rx_holder = Some(typing_rx_inner);

            // Publish late-bound state to the event loop via watch channel.
            // This makes OMEMO manager, pubsub_responses, typing_tx available
            // to the event loop without any mutex locks.
            chatterbox::xmpp::publish_late_state(&xmpp_client);

            // Initialize Service Discovery (XEP-0030)
            // TODO: Fix type mismatch between XMPPClient and AsyncClient
            // if let Some(client_ref) = chatterbox::xmpp::get_global_xmpp_client().await {
            //     let service_discovery = ServiceDiscovery::new(client_ref);
            //     if let Err(e) = service_discovery.advertise_features().await {
            //         warn!("Failed to advertise service discovery features: {}", e);
            //     }
            // }
        }
        Err(e) => {
            println!("Connection failed!");

            // Get detailed error information - break it into multiple lines for better readability
            let error_details = format!("Connection to XMPP server failed: {}", e);
            let error_display = format!(
                "Failed to connect to {}@{}\n\
                 Details: {}\n\
                 Please check:\n\
                 - Network connectivity\n\
                 - Server address is correct\n\
                 - Username and password are correct\n\
                 - Server is running and accepting connections",
                username, server, error_details
            );

            // Log the error
            error!("{}", error_details);

            // Display error to user
            eprintln!("{}", error_display);

            return Err(anyhow::anyhow!(error_details));
        }
    }

    // Hand off to the application event loop
    let typing_rx = typing_rx_holder.expect("typing_rx must be set after successful connection");
    app::run_app(xmpp_client, msg_rx, typing_rx, args.disable_mam).await
}
