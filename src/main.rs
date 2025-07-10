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
use himmelblau::error::MsalError;
use himmelblau::graph::Graph;
use himmelblau::{AuthOption, BrokerClientApplication, EnrollAttrs, MFAAuthContinue};
use kanidm_hsm_crypto::soft::SoftTpm;
use kanidm_hsm_crypto::{AuthValue, BoxedDynTpm, LoadableIdentityKey, LoadableMsOapxbcRsaKey, Tpm};
use regex::Regex;
use rpassword::read_password;
use std::io;
use std::io::Write;
use std::process::ExitCode;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use authenticator::{
    authenticatorservice::{AuthenticatorService, SignArgs},
    ctap2::server::{
        AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    },
    statecallback::StateCallback,
    Pin, StatusPinUv, StatusUpdate,
};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, to_string as json_to_string, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::mpsc::{channel, RecvError};
use std::thread;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tracing::{debug, info};

mod db;
use crate::db::Db;

use clap::Parser;
include!("./opt/tool.rs");

const DEFAULT_DB_PATH: &str = "/var/cache/himmelblaud/himmelblau.cache.db";
const DEFAULT_HSM_PIN_PATH: &str = "/var/lib/himmelblaud/hsm-pin";

fn split_username(username: &str) -> Option<(&str, &str)> {
    let tup: Vec<&str> = username.split('@').collect();
    if tup.len() == 2 {
        return Some((tup[0], tup[1]));
    }
    None
}

async fn fido_auth(flow: &MFAAuthContinue) -> Result<String, Box<dyn std::error::Error>> {
    // Initialize AuthenticatorService
    let mut manager = AuthenticatorService::new()?;
    manager.add_u2f_usb_hid_platform_transports();

    let fido_challenge = flow
        .fido_challenge
        .clone()
        .ok_or("sFidoChallenge missing from response")?;

    let challenge_str = json_to_string(&json!({
        "type": "webauthn.get",
        "challenge": URL_SAFE_NO_PAD.encode(fido_challenge.clone()),
        "origin": "https://login.microsoft.com"
    }))?;

    // Create a channel for status updates
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(..)) => {
                panic!("STATUS: This can't happen when doing non-interactive usage");
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                println!("STATUS: Please select a device by touching one of them.");
            }
            Ok(StatusUpdate::PresenceRequired) => {
                println!("STATUS: waiting for user presence");
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))) => {
                let raw_pin =
                    rpassword::prompt_password("Enter PIN: ").expect("Failed to read PIN");
                sender.send(Pin::new(&raw_pin)).expect("Failed to send PIN");
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts))) => {
                println!(
                    "Wrong PIN! {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );
                let raw_pin =
                    rpassword::prompt_password("Enter PIN: ").expect("Failed to read PIN");
                sender.send(Pin::new(&raw_pin)).expect("Failed to send PIN");
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                panic!("Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug in again.")
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                panic!("Too many failed attempts. Your device has been blocked. Reset it.")
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts))) => {
                println!(
                    "Wrong UV! {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::UvBlocked)) => {
                println!("Too many failed UV-attempts.");
                continue;
            }
            Ok(StatusUpdate::PinUvError(e)) => {
                panic!("Unexpected error: {:?}", e)
            }
            Ok(StatusUpdate::SelectResultNotice(_, _)) => {
                panic!("Unexpected select device notice")
            }
            Err(RecvError) => {
                println!("STATUS: end");
                return;
            }
        }
    });

    let fido_allow_list = flow
        .fido_allow_list
        .clone()
        .ok_or("arrFidoAllowList missing from response".to_string())?;

    let allow_list: Vec<PublicKeyCredentialDescriptor> = fido_allow_list
        .into_iter()
        .filter_map(|id| match STANDARD.decode(id) {
            Ok(decoded_id) => Some(PublicKeyCredentialDescriptor {
                id: decoded_id,
                transports: vec![],
            }),
            Err(e) => {
                error!("Failed decoding allow list id: {:?}", e);
                None
            }
        })
        .collect();

    // Prepare SignArgs
    let chall_bytes = Sha256::digest(challenge_str.clone()).into();
    let ctap_args = SignArgs {
        client_data_hash: chall_bytes,
        origin: "https://login.microsoft.com".to_string(),
        relying_party_id: "login.microsoft.com".to_string(),
        allow_list,
        user_verification_req: UserVerificationRequirement::Preferred,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    // Perform authentication
    let (sign_tx, sign_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        sign_tx.send(rv).unwrap();
    }));

    match manager.sign(25000, ctap_args, status_tx.clone(), callback) {
        Ok(_) => (),
        Err(e) => panic!("Couldn't sign: {:?}", e),
    }

    let assertion_result = sign_rx.recv()??;

    let credential_id = assertion_result
        .assertion
        .credentials
        .as_ref()
        .map(|cred| cred.id.clone())
        .unwrap_or_default();
    let auth_data = assertion_result.assertion.auth_data;
    let signature = assertion_result.assertion.signature;
    let user_handle = assertion_result
        .assertion
        .user
        .as_ref()
        .map(|user| user.id.clone())
        .unwrap_or_default();
    let json_response = json!({
        "id": URL_SAFE_NO_PAD.encode(credential_id),
        "clientDataJSON": URL_SAFE_NO_PAD.encode(challenge_str),
        "authenticatorData": URL_SAFE_NO_PAD.encode(auth_data.to_vec()),
        "signature": URL_SAFE_NO_PAD.encode(signature),
        "userHandle": URL_SAFE_NO_PAD.encode(user_handle),
    });

    // Convert the JSON response to a string
    Ok(json_to_string(&json_response).unwrap())
}

fn is_valid_base64url(s: &str) -> bool {
    URL_SAFE_NO_PAD.decode(s).is_ok_and(|v| v.len() >= 10)
}

fn obfuscate_jwt_and_jwe(input: &str) -> String {
    let jwt_re = Regex::new(r"([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]*)").unwrap();
    let jwe_re = Regex::new(r"([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]+)").unwrap();

    let mut result = jwe_re
        .replace_all(input, |caps: &regex::Captures| {
            if (1..=5).all(|i| is_valid_base64url(&caps[i])) {
                "*".repeat(caps[0].len())
            } else {
                caps[0].to_string()
            }
        })
        .into_owned();

    result = jwt_re
        .replace_all(&result, |caps: &regex::Captures| {
            let h = &caps[1];
            let p = &caps[2];
            if is_valid_base64url(h) && is_valid_base64url(p) {
                debug!("MATCHED: {}", caps[0].to_string());
                "*".repeat(caps[0].len())
            } else {
                caps[0].to_string()
            }
        })
        .into_owned();

    result
}

fn obfuscate_refresh_tokens(input: &str) -> String {
    let re = Regex::new(r"\d\.[A-Za-z0-9\-_]+(?:\.[A-Za-z0-9\-_]+)+").unwrap();

    re.replace_all(input, |caps: &regex::Captures| {
        let token = &caps[0];
        let parts: Vec<&str> = token.split('.').collect();

        let mut valid_parts = 0;
        for part in &parts[1..] {
            // skip version digit
            if is_valid_base64url(part) {
                valid_parts += 1;
            }
        }

        if valid_parts >= 2 {
            debug!("MATCHED: {}", token.to_string());
            "*".repeat(token.len())
        } else {
            token.to_string()
        }
    })
    .into_owned()
}

fn is_base64_json(s: &str) -> bool {
    // Try base64url first
    if let Ok(decoded) = URL_SAFE_NO_PAD.decode(s) {
        if let Ok(decoded_str) = std::str::from_utf8(&decoded) {
            return serde_json::from_str::<Value>(decoded_str).is_ok();
        }
    }
    // Then try standard base64
    if let Ok(decoded) = STANDARD_NO_PAD.decode(s) {
        if let Ok(decoded_str) = std::str::from_utf8(&decoded) {
            return serde_json::from_str::<Value>(decoded_str).is_ok();
        }
    }
    false
}

fn obfuscate_base64_json_blobs(input: &str) -> String {
    let re = Regex::new(r"[A-Za-z0-9\-_]{20,}").unwrap();

    re.replace_all(input, |caps: &regex::Captures| {
        let candidate = &caps[0];
        if is_base64_json(candidate) {
            debug!("MATCHED: {}", candidate.to_string());
            "*".repeat(candidate.len())
        } else {
            candidate.to_string()
        }
    })
    .into_owned()
}

fn decode_any_base64(candidate: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(candidate)
        .or_else(|_| URL_SAFE.decode(candidate))
        .or_else(|_| STANDARD_NO_PAD.decode(candidate))
        .or_else(|_| URL_SAFE_NO_PAD.decode(candidate))
        .ok()
}

fn obfuscate_kerberos_tgts(input: &str) -> String {
    let re = Regex::new(r"[A-Za-z0-9\+/=]{500,}").unwrap(); // include + / = explicitly

    re.replace_all(input, |caps: &regex::Captures| {
        let candidate = &caps[0];

        if let Some(decoded) = decode_any_base64(candidate) {
            if is_likely_kerberos_ticket(&decoded) {
                debug!("MATCHED: {}", candidate.to_string());
                return "*".repeat(candidate.len());
            }
        }

        candidate.to_string()
    })
    .into_owned()
}

fn is_likely_kerberos_ticket(decoded: &[u8]) -> bool {
    // DER typically starts with SEQUENCE (0x30) or application-specific tag (0x6B)
    matches!(decoded.first(), Some(0x30) | Some(0x6B))
}

fn extract_tenant_guid(input: &str) -> Option<String> {
    let re = Regex::new(r#""tenantId"\s*:\s*"([0-9a-fA-F\-]{36})""#).unwrap();
    re.captures(input).map(|caps| caps[1].to_string())
}

fn obfuscate_tenant_id(input: &str) -> String {
    if let Some(tenant_guid) = extract_tenant_guid(input) {
        debug!("MATCHED: {}", tenant_guid.to_string());
        input.replace(&tenant_guid, "00000000-0000-0000-0000-000000000000")
    } else {
        input.to_string()
    }
}

fn obfuscate_flow_tokens(input: &str) -> String {
    let re = Regex::new(r"[A-Za-z0-9\-_]{100,}").unwrap();

    re.replace_all(input, |caps: &regex::Captures| {
        let candidate = &caps[0];

        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(candidate) {
            if decoded.len() >= 30 && is_likely_flow_token(&decoded) {
                debug!("MATCHED: {}", candidate.to_string());
                return "*".repeat(candidate.len());
            }
        }

        candidate.to_string()
    })
    .into_owned()
}

fn is_likely_flow_token(decoded: &[u8]) -> bool {
    decoded.starts_with(&[0x01, 0x00, 0x01])
}

fn is_likely_request_object(decoded: &[u8]) -> bool {
    decoded.starts_with(&[0xAD, 0x04])
}

fn obfuscate_request_objects(input: &str) -> String {
    let re = Regex::new(r"rQ[A-Za-z0-9\-_]{50,}").unwrap();

    re.replace_all(input, |caps: &regex::Captures| {
        let candidate = &caps[0];
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(candidate) {
            if decoded.len() >= 30 && is_likely_request_object(&decoded) {
                debug!("MATCHED: {}", candidate.to_string());
                return "*".repeat(candidate.len());
            }
        }
        candidate.to_string()
    })
    .into_owned()
}

fn extract_domain(input: &str) -> Option<String> {
    let re = Regex::new(r"domain=([a-zA-Z0-9\.-]+)").unwrap();
    re.captures(input).map(|caps| caps[1].to_string())
}

fn obfuscate_domain(input: &str) -> String {
    if let Some(domain) = extract_domain(input) {
        debug!("MATCHED: {}", domain);
        let replacement = "*".repeat(domain.len());
        input.replace(&domain, &replacement)
    } else {
        input.to_string()
    }
}

fn obfuscate_custom_strings(input: &str, custom_strings: &[&str]) -> String {
    let mut output = input.to_string();
    for &secret in custom_strings {
        if !secret.is_empty() {
            let replacement = "*".repeat(secret.len());
            debug!("MATCHED: {}", secret);
            output = output.replace(secret, &replacement);
        }
    }
    output
}

fn obfuscate_text(input: &str, custom_strings: &[&str]) -> String {
    let mut result = input.to_string();
    result = obfuscate_custom_strings(&result, custom_strings);
    result = obfuscate_tenant_id(&result);
    result = obfuscate_domain(&result);
    result = obfuscate_jwt_and_jwe(&result);
    result = obfuscate_refresh_tokens(&result);
    result = obfuscate_base64_json_blobs(&result);
    result = obfuscate_kerberos_tgts(&result);
    result = obfuscate_flow_tokens(&result);
    result = obfuscate_request_objects(&result);

    result
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let opt = CirrusScopeParser::parse();

    let debug = match opt.commands {
        CirrusScopeOpt::AuthTest {
            debug,
            account_id: _,
        } => debug,
        CirrusScopeOpt::EnrollmentTest {
            debug,
            account_id: _,
        } => debug,
        CirrusScopeOpt::Obfuscate {
            debug,
            custom: _,
            input: _,
            output: _,
        } => debug,
        CirrusScopeOpt::RefreshTokenAcquire {
            debug,
            account_id: _,
        } => debug,
        CirrusScopeOpt::ProvisionHelloKeyTest {
            debug,
            account_id: _,
        } => debug,
        CirrusScopeOpt::Version { debug } => debug,
    };

    let mut subscriber_builder = FmtSubscriber::builder();
    if debug {
        std::env::set_var("RUST_LOG", "debug");
        subscriber_builder = subscriber_builder.with_max_level(Level::TRACE);
    }
    let subscriber = subscriber_builder.finish();

    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        error!(?e, "Failed setting up default tracing subscriber.");
        return ExitCode::FAILURE;
    }

    macro_rules! init {
        ($account_id:expr) => {{
            let (_, domain) = match split_username(&$account_id) {
                Some(out) => out,
                None => {
                    error!("Could not split domain from input username");
                    return ExitCode::FAILURE;
                }
            };

            let graph = match Graph::new("odc.officeapps.live.com", &domain, None, None, None).await
            {
                Ok(graph) => graph,
                Err(e) => {
                    error!("Failed discovering tenant: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let authority_host = match graph.authority_host().await {
                Ok(authority_host) => authority_host,
                Err(e) => {
                    error!("Failed discovering authority_host: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let tenant_id = match graph.tenant_id().await {
                Ok(tenant_id) => tenant_id,
                Err(e) => {
                    error!("Failed discovering tenant_id: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let authority = format!("https://{}/{}", authority_host, tenant_id);

            (domain, authority)
        }};
    }

    macro_rules! client {
        ($authority:expr, $transport_key:expr, $cert_key:expr) => {{
            match BrokerClientApplication::new(Some(&$authority), None, $transport_key, $cert_key) {
                Ok(app) => app,
                Err(e) => {
                    error!("Failed creating app: {:?}", e);
                    return ExitCode::FAILURE;
                }
            }
        }};
    }

    macro_rules! auth {
        ($app:expr, $account_id:expr) => {{
            let auth_options = vec![AuthOption::Fido, AuthOption::Passwordless];
            let auth_init = match $app.check_user_exists(&$account_id, &auth_options).await {
                Ok(auth_init) => auth_init,
                Err(e) => {
                    error!("Failed checking if user exists: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };
            debug!("User {} exists? {}", &$account_id, auth_init.exists());

            let password = if !auth_init.passwordless() {
                print!("{} password: ", &$account_id);
                io::stdout().flush().unwrap();
                match read_password() {
                    Ok(password) => Some(password),
                    Err(e) => {
                        error!("{:?}", e);
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                None
            };

            let mut mfa_req = match $app
                .initiate_acquire_token_by_mfa_flow_for_device_enrollment(
                    &$account_id,
                    password.as_deref(),
                    &auth_options,
                    Some(auth_init),
                )
                .await
            {
                Ok(mfa) => mfa,
                Err(e) => match e {
                    MsalError::PasswordRequired => {
                        print!("{} password: ", &$account_id);
                        io::stdout().flush().unwrap();
                        let password = match read_password() {
                            Ok(password) => Some(password),
                            Err(e) => {
                                error!("{:?}", e);
                                return ExitCode::FAILURE;
                            }
                        };
                        let auth_init =
                            match $app.check_user_exists(&$account_id, &auth_options).await {
                                Ok(auth_init) => auth_init,
                                Err(e) => {
                                    error!("Failed checking if user exists: {:?}", e);
                                    return ExitCode::FAILURE;
                                }
                            };
                        match $app
                            .initiate_acquire_token_by_mfa_flow_for_device_enrollment(
                                &$account_id,
                                password.as_deref(),
                                &auth_options,
                                Some(auth_init),
                            )
                            .await
                        {
                            Ok(mfa) => mfa,
                            Err(e) => {
                                error!("{:?}", e);
                                return ExitCode::FAILURE;
                            }
                        }
                    }
                    _ => {
                        error!("{:?}", e);
                        return ExitCode::FAILURE;
                    }
                },
            };
            print!("{}", mfa_req.msg);
            io::stdout().flush().unwrap();

            match mfa_req.mfa_method.as_str() {
                "FidoKey" => {
                    // Create the assertion
                    let assertion = match fido_auth(&mfa_req).await {
                        Ok(assertion) => assertion,
                        Err(e) => {
                            error!("FIDO ASSERTION FAIL: {:?}", e);
                            return ExitCode::FAILURE;
                        }
                    };
                    match $app
                        .acquire_token_by_mfa_flow(
                            &$account_id,
                            Some(&assertion),
                            None,
                            &mut mfa_req,
                        )
                        .await
                    {
                        Ok(token) => token,
                        Err(e) => {
                            error!("MFA FAIL: {:?}", e);
                            return ExitCode::FAILURE;
                        }
                    }
                }
                "AccessPass" | "PhoneAppOTP" | "OneWaySMS" | "ConsolidatedTelephony" => {
                    //io::stdout().flush().unwrap();
                    let input = match read_password() {
                        Ok(password) => password,
                        Err(e) => {
                            error!("{:?} ", e);
                            return ExitCode::FAILURE;
                        }
                    };
                    match $app
                        .acquire_token_by_mfa_flow(&$account_id, Some(&input), None, &mut mfa_req)
                        .await
                    {
                        Ok(token) => token,
                        Err(e) => {
                            error!("MFA FAIL: {:?}", e);
                            return ExitCode::FAILURE;
                        }
                    }
                }
                _ => {
                    let mut poll_attempt = 1;
                    let polling_interval = mfa_req.polling_interval.unwrap_or(5000);
                    loop {
                        match $app
                            .acquire_token_by_mfa_flow(
                                &$account_id,
                                None,
                                Some(poll_attempt),
                                &mut mfa_req,
                            )
                            .await
                        {
                            Ok(token) => break token,
                            Err(e) => match e {
                                MsalError::MFAPollContinue => {
                                    poll_attempt += 1;
                                    sleep(Duration::from_millis(polling_interval.into()));
                                    continue;
                                }
                                e => {
                                    error!("MFA FAIL: {:?}", e);
                                    return ExitCode::FAILURE;
                                }
                            },
                        }
                    }
                }
            }
        }};
    }

    macro_rules! obtain_prt {
        ($app:expr, $token:expr, $tpm:expr, $machine_key:expr, $scope:expr, $resource:expr) => {{
            match $app
                .acquire_token_by_refresh_token(
                    &$token.refresh_token,
                    $scope,
                    $resource,
                    &mut $tpm,
                    &$machine_key,
                )
                .await
            {
                Ok(token) => token,
                Err(e) => {
                    error!("{:?}", e);
                    return ExitCode::FAILURE;
                }
            }
        }};
    }

    macro_rules! obtain_host_data {
        ($domain:expr) => {{
            // Make sure the command is running as root
            if unsafe { libc::geteuid() } != 0 {
                error!("This command must be run as root.");
                return ExitCode::FAILURE;
            }

            // Fetch the auth_value from Himmelblau
            let path_buf = match PathBuf::from_str(DEFAULT_HSM_PIN_PATH) {
                Ok(path_buf) => path_buf,
                Err(e) => {
                    error!(?e, "Failed to construct pathbuf for hsm pin path");
                    return ExitCode::FAILURE;
                }
            };
            if !path_buf.exists() {
                error!("HSM PIN file '{}' not found", DEFAULT_HSM_PIN_PATH);
                return ExitCode::FAILURE;
            }
            let mut file = match File::open(DEFAULT_HSM_PIN_PATH).await {
                Ok(file) => file,
                Err(e) => {
                    error!("Failed reading the HSM PIN: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };
            let mut hsm_pin = vec![];
            match file.read_to_end(&mut hsm_pin).await {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed reading the HSM PIN: {:?}", e);
                    return ExitCode::FAILURE;
                }
            }
            let auth_value = match AuthValue::try_from(hsm_pin.as_slice()) {
                Ok(av) => av,
                Err(e) => {
                    error!("invalid hsm pin: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let mut db = match Db::new(DEFAULT_DB_PATH) {
                Ok(db) => db,
                Err(e) => {
                    error!("Failed loading Himmelblau cache: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let mut tpm = BoxedDynTpm::new(SoftTpm::new());

            // Fetch the machine key
            let loadable_machine_key = match db.get_hsm_machine_key() {
                Ok(Some(lmk)) => lmk,
                Err(e) => {
                    error!("Unable to access hsm loadable machine key: {:?}", e);
                    return ExitCode::FAILURE;
                }
                _ => {
                    error!("Unable to access hsm loadable machine key.");
                    return ExitCode::FAILURE;
                }
            };
            let machine_key = match tpm.machine_key_load(&auth_value, &loadable_machine_key) {
                Ok(mk) => mk,
                Err(e) => {
                    error!("Unable to load machine root key: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            // Fetch the transport key
            let tranport_key_tag = format!("{}/transport", $domain);
            let loadable_transport_key: LoadableMsOapxbcRsaKey =
                match db.get_tagged_hsm_key(&tranport_key_tag) {
                    Ok(Some(ltk)) => ltk,
                    Err(e) => {
                        error!("Unable to access hsm loadable transport key: {:?}", e);
                        return ExitCode::FAILURE;
                    }
                    _ => {
                        error!("Unable to access hsm loadable transport key.");
                        return ExitCode::FAILURE;
                    }
                };

            // Fetch the certificate key
            let cert_key_tag = format!("{}/certificate", $domain);
            let loadable_cert_key: LoadableIdentityKey = match db.get_tagged_hsm_key(&cert_key_tag)
            {
                Ok(Some(ltk)) => ltk,
                Err(e) => {
                    error!("Unable to access hsm certificate key: {:?}", e);
                    return ExitCode::FAILURE;
                }
                _ => {
                    error!("Unable to access hsm certificate key.");
                    return ExitCode::FAILURE;
                }
            };

            (tpm, loadable_transport_key, loadable_cert_key, machine_key)
        }};
    }

    match opt.commands {
        CirrusScopeOpt::AuthTest {
            debug: _,
            account_id,
        } => {
            let (_domain, authority) = init!(account_id);
            let app = client!(authority, None, None);
            let token = auth!(app, account_id);
            println!(
                "access_token: {}, spn: {}, uuid: {:?}, mfa?: {:?}",
                token.access_token.clone().unwrap(),
                token.spn().unwrap(),
                token.uuid().unwrap(),
                token.amr_mfa().unwrap()
            );
            ExitCode::SUCCESS
        }
        CirrusScopeOpt::EnrollmentTest {
            debug: _,
            account_id,
        } => {
            let (domain, authority) = init!(account_id);
            let mut app = client!(authority, None, None);
            let token = auth!(app, account_id);

            // Danger zone! This command leaves artifacts in the Entra Id directory
            info!("Attempting device enrollment");
            let mut tpm = BoxedDynTpm::new(SoftTpm::new());
            let auth_str = AuthValue::generate().expect("Failed to create hex pin");
            let auth_value = AuthValue::from_str(&auth_str).expect("Unable to create auth value");
            // Request a new machine-key-context. This key "owns" anything
            // created underneath it.
            let loadable_machine_key = tpm
                .machine_key_create(&auth_value)
                .expect("Unable to create new machine key");
            let machine_key = tpm
                .machine_key_load(&auth_value, &loadable_machine_key)
                .expect("Unable to load machine key");
            let attrs = match EnrollAttrs::new(
                domain.to_string(),
                Some("cirrus-scope-test-machine".to_string()),
                None,
                None,
                None,
            ) {
                Ok(attrs) => attrs,
                Err(e) => {
                    error!("{:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            let (_transport_key, _cert_key, device_id) = match app
                .enroll_device(&token.refresh_token, attrs, &mut tpm, &machine_key)
                .await
            {
                Ok((transport_key, cert_key, device_id)) => (transport_key, cert_key, device_id),
                Err(e) => {
                    error!("{:?}", e);
                    return ExitCode::FAILURE;
                }
            };
            println!("Enrolled with device id: {}", device_id);
            ExitCode::SUCCESS
        }
        CirrusScopeOpt::Obfuscate {
            debug: _,
            custom,
            input,
            output,
        } => {
            let content = match std::fs::read_to_string(input) {
                Ok(content) => content,
                Err(e) => {
                    error!("Failed to read input file: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };
            let custom_refs: Vec<&str> = custom.iter().map(|s| s.as_str()).collect();
            let obfuscated = obfuscate_text(&content, &custom_refs);
            match std::fs::write(output, obfuscated) {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to write output file: {:?}", e);
                    return ExitCode::FAILURE;
                }
            };

            ExitCode::SUCCESS
        }
        CirrusScopeOpt::RefreshTokenAcquire {
            debug: _,
            account_id,
        } => {
            let (domain, authority) = init!(account_id);
            let (mut tpm, loadable_transport_key, loadable_cert_key, machine_key) =
                obtain_host_data!(domain);
            let app = client!(
                authority,
                Some(loadable_transport_key),
                Some(loadable_cert_key)
            );
            let token = auth!(app, account_id);

            info!("Obtain PRT from refresh token");
            let token = obtain_prt!(app, token, tpm, machine_key, vec![], None);
            println!(
                "access_token: {}, spn: {}, uuid: {:?}, mfa?: {:?}",
                token.access_token.clone().unwrap(),
                token.spn().unwrap(),
                token.uuid().unwrap(),
                token.amr_mfa().unwrap()
            );
            ExitCode::SUCCESS
        }
        CirrusScopeOpt::ProvisionHelloKeyTest {
            debug: _,
            account_id,
        } => {
            let (domain, authority) = init!(account_id);
            let (mut tpm, loadable_transport_key, loadable_cert_key, machine_key) =
                obtain_host_data!(domain);
            let app = client!(
                authority,
                Some(loadable_transport_key),
                Some(loadable_cert_key)
            );
            let token = auth!(app, account_id);
            let token2 = obtain_prt!(app, token, tpm, machine_key, vec![], None);

            info!("Provision hello key");
            let win_hello_key = match app
                .provision_hello_for_business_key(&token2, &mut tpm, &machine_key, "123456")
                .await
            {
                Ok(win_hello_key) => win_hello_key,
                Err(e) => {
                    error!("{:?}", e);
                    return ExitCode::FAILURE;
                }
            };
            println!("{:?}", win_hello_key);

            info!("Acquire token via hello key");
            let token4 = match app
                .acquire_token_by_hello_for_business_key(
                    &account_id,
                    &win_hello_key,
                    vec![],
                    None,
                    &mut tpm,
                    &machine_key,
                    "123456",
                )
                .await
            {
                Ok(token) => token,
                Err(e) => {
                    error!("{:?}", e);
                    return ExitCode::FAILURE;
                }
            };
            println!(
                "access_token: {}, spn: {}, uuid: {:?}, mfa?: {:?}",
                token4.access_token.clone().unwrap(),
                token4.spn().unwrap(),
                token4.uuid().unwrap(),
                token4.amr_mfa().unwrap()
            );

            if token4.prt.is_none() {
                error!("Failed to find PRT in Hello token!");
            }
            ExitCode::SUCCESS
        }
        CirrusScopeOpt::Version { debug: _ } => {
            println!("cirrus-scope {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}
