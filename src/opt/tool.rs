/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
use clap::Subcommand;

#[derive(Debug, Subcommand)]
#[clap(about = "Cirrus Scope Utility")]
pub enum CirrusScopeOpt {
    /// Test authentication of a user using MFA.
    ///
    /// This command initiates an MFA flow (using FIDO, PhoneAppOTP, etc.) to validate user authentication.
    /// It simulates the process of signing in by invoking functions like `fido_auth` and logging detailed
    /// debug information if enabled. The provided `account_id` specifies which user account to test.
    AuthTest {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: String,
    },
    /// Test device enrollment.
    ///
    /// WARNING! This enrollment leaves artifacts in Entra Id, and does not actually enroll the
    /// host! Proceed only if you are capable of cleaning up the `cirrus-scope-test-machine`
    /// object from the directory. This command is for investigation and testing purposes only!
    ///
    /// This command performs the device enrollment process by utilizing Soft HSM-based machine key creation,
    /// initiating the MFA enrollment flow, and eventually enrolling the device. Detailed logs are captured
    /// when debug mode is enabled, and the `account_id` identifies the target account.
    EnrollmentTest {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: String,
    },
    /// Acquire a new access token using a refresh token.
    ///
    /// This command tests the token refresh mechanism by acquiring a new access token through an enrollment
    /// refresh token. It is designed to verify that the refresh flow works correctly, with optional debug
    /// output for tracing the HTTP and token operations. The `account_id` specifies the account under test.
    RefreshTokenAcquire {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: String,
    },
    /// Test provisioning of a Hello for Business key.
    ///
    /// WARNING! This key enrollment leaves key artifacts attached to the authenticating user. This
    /// does NOT store a Hello key for the user on the device. This command is for investigation
    /// and testing purposes only!
    ///
    /// This command provisions a Hello key by generating, storing, and initializing it via TPM.
    /// It performs the Hello key creation process needed for secure device authentication. It then
    /// validates that Hello key by fetching an access token with a PRT.
    ProvisionHelloKeyTest {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: String,
    },
    /// Show the version of this tool.
    Version {
        #[clap(short, long)]
        debug: bool,
    }
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Cirrus Scope Utility")]
pub struct CirrusScopeParser {
    #[clap(subcommand)]
    pub commands: CirrusScopeOpt,
}
