use clap::{Parser, Subcommand};

pub mod account;
pub mod certificate;
pub mod check;
pub mod device;
pub mod device_id;
pub mod device_info;
pub mod macho;
pub mod mount;
pub mod pair;
pub mod screenshot;
pub mod sign;
pub mod sign_rsd;

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
    /// Sign an iOS app bundle with certificate and provisioning profile (RSD)
    SignRsd(sign_rsd::SignArgs),
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
    /// Show device information via usbmuxd/lockdown
    #[command(name = "device_info", alias = "device-info")]
    DeviceInfo(device_info::DeviceInfoArgs),
    /// Pair a device over network (IP/port)
    Pair(pair::PairArgs),
    /// Check PublicStaging via AFC and list files
    Check(check::CheckArgs),
    /// Mount a personalized developer disk image on an iOS device over an RSD tunnel
    Mount(mount::MountArgs),
    /// Take a screenshot from an iOS device over an RSD tunnel
    Screenshot(screenshot::ScreenshotArgs),
}
