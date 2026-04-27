//! Network federation CLI commands.
//!
//! Provides `sesame network identity`, `sesame network peers`,
//! `sesame network discover`, `sesame network status`.
//!
//! Stubs — Milestones 1 and 2 implement the full functionality.

use crate::cli::NetworkCmd;

pub(crate) async fn cmd_network(sub: NetworkCmd) -> anyhow::Result<()> {
    match sub {
        NetworkCmd::Identity { json: _ } => {
            eprintln!("sesame network identity — not yet implemented (requires Milestone 1)");
            Ok(())
        }
        NetworkCmd::Peers => {
            eprintln!("sesame network peers — not yet implemented (requires Milestone 1)");
            Ok(())
        }
        NetworkCmd::Discover => {
            eprintln!("sesame network discover — not yet implemented (requires Milestone 2)");
            Ok(())
        }
        NetworkCmd::Status => {
            eprintln!("sesame network status — not yet implemented (requires Milestone 1)");
            Ok(())
        }
    }
}
