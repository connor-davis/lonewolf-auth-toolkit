use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Error;
use rand::{thread_rng, Rng};
use totp_rs::{Rfc6238, TOTP};

/// Generate a random string
///
/// ### Example
/// ```rust
/// use lonewolf_auth_toolkit::mfa::generate_random_string;
///
/// let random_string = generate_random_string();
/// ```
pub fn generate_random_string() -> String {
    let mut rng = thread_rng();
    let random_bytes: [u8; 32] = rng.gen();
    let hex_string: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    hex_string
}

/// Generate a TOTP 6 Digit QR Code
///
/// ### Example
/// ```rust
/// use lonewolf_auth_toolkit::mfa::generate;
///
/// #[tokio::main]
/// pub async fn main() -> Result<(), anyhow::Error> {
///     let result = generate("SomeIssuer".to_string(), "SomeAccountName".to_string()).await?;
/// 
///     println!("{:?}", result.0);
///     println!("{:?}", result.1);
/// 
///     Ok(())
/// }
/// ```
pub async fn generate(issuer: String, account_name: String) -> Result<(String, String), Error> {
    let secret_string = generate_random_string();
    let mut rfc = Rfc6238::with_defaults(secret_string.clone().into_bytes().to_vec())?;

    rfc.digits(6)?;
    rfc.issuer(issuer);
    rfc.account_name(account_name);

    let totp = TOTP::from_rfc6238(rfc)?;
    let qr_code = totp.get_qr_base64();

    match qr_code {
        Ok(qr_code) => Ok((qr_code, secret_string)),
        Err(error) => Err(Error::msg(error)),
    }
}

/// Verify a TOTP 6 Digit Code
/// 
/// ### Example
/// ```rust
/// use lonewolf_auth_toolkit::mfa::verify;
/// 
/// #[tokio::main]
/// pub async fn main() -> Result<(), anyhow::Error> {
///     let verified = verify("123456".to_string(), "5BAD23B477D625825019A4C895E8C5B8D22A88D3193E6928B7FC7AEFF1CC578F2A9551A1919ADE27EC50E48DFD4A2F95D9B52636C141E5B5FADE5C24A0EC71E7".to_string()).await?;
/// 
///     Ok(())
/// }
/// ```
pub async fn verify(code: String, secret: String) -> Result<bool, Error> {
    let mut rfc = Rfc6238::with_defaults(secret.clone().into_bytes().to_vec())?;

    rfc.digits(6)?;

    let totp = TOTP::from_rfc6238(rfc)?;
    let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let token = totp.generate(time);

    Ok(code == token)
}