use clap::{Parser, Subcommand};

pub mod account;
pub mod certificate;
pub mod check;
pub mod device;
pub mod device_id;
pub mod macho;
pub mod pair;
pub mod sign;

#[derive(Debug, Parser)]
#[command(
    name = "plumesign",
    author,
    version,
    about = "iOS code signing and inspection tool",
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Sign an iOS app bundle with certificate and provisioning profile
    Sign(sign::SignArgs),
    /// Inspect Mach-O binaries
    MachO(macho::MachArgs),
    /// Manage Apple Developer account authentication
    Account(account::AccountArgs),
    /// Certificate management (list / revoke)
    Certificate(certificate::CertificateArgs),
    /// Device management commands
    Device(device::DeviceArgs),
    /// List connected devices (udid, id, name)
    DeviceId(device_id::DeviceIdArgs),
    /// Pair a device (wired or wireless)
    Pair(pair::PairArgs),
    /// Check PublicStaging via AFC and list files
    Check(check::CheckArgs),
}
