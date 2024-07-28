use actix_web::{http::header, HttpRequest};
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use crate::ADMIN_TOKEN;

#[derive(Deserialize, Serialize, Debug)]
pub struct ApplicationAuth {
  pub application_id: String,
  pub name: String,
  pub permissions: Vec<u8>
}


pub fn get_bearer_token(req: HttpRequest) -> Option<String> {
  let token = req.headers().get(header::AUTHORIZATION);

  // check if there is a token
  if let Some(token) = token {
    let token = token.to_str().unwrap().strip_prefix("Bearer ").unwrap();

    return if token == ADMIN_TOKEN.as_str() {
      Some(String::from(token))
    } else {
      None
    };
  }

  None
}

pub fn get_jwt_application_token(req: HttpRequest) -> Option<BTreeMap<String, String>> {
  let token = req.headers().get(header::AUTHORIZATION);

  // check if there is a token
  if let Some(token) = token {
    let secret = std::env::var("SECRET").unwrap();
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_str().as_bytes()).unwrap();
    let token = token.to_str().unwrap().strip_prefix("Bearer ").unwrap();
    let validate = token.verify_with_key(&key);
    
    if validate.is_err() {
      return None;
    }

    let validate: BTreeMap<String, String> = validate.unwrap();

    return Some(validate);
  }

  None
}


pub fn create_application_token(application: ApplicationAuth) -> String {
  let secret = std::env::var("SECRET").unwrap();
  let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_str().as_bytes()).unwrap();
  
  let mut claims = BTreeMap::new();

  claims.insert("application_id", application.application_id);
  
  let token_str = claims.sign_with_key(&key).unwrap();

  token_str.to_string()
}