use std::collections::HashMap;

use pest::{Parser, iterators::Pair};
use pest_derive::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[grammar = "jgpg.pest"]
pub struct GpgKeyListParser;

#[derive(Debug, Serialize, Deserialize)]
pub struct Key {
    pub key_type: String,
    pub created: String,
    pub can_sign: bool,
    pub can_certify: bool,
    pub can_encrypt: bool,
    pub can_authenticate: bool,
    pub expires: Option<String>,
    pub id: Option<String>,
    pub fingerprint: Option<String>,
    pub trust_level: String,
    pub real_name: String,
    pub email: Option<String>,
    pub sub_keys: Vec<SubKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubKey {
    pub key_type: String,
    pub created: String,
    pub can_sign: bool,
    pub can_certify: bool,
    pub can_encrypt: bool,
    pub can_authenticate: bool,
    pub expires: Option<String>,
}

pub fn to_string_pretty(input: &String) -> Result<String, Box<dyn std::error::Error>> {
    let keyrings = parse(input.trim())?;
    let json = serde_json::to_string_pretty(&keyrings)?;
    Ok(json)
}

pub fn to_string(input: &String) -> Result<String, Box<dyn std::error::Error>> {
    let keyrings = parse(input.trim())?;
    let json = serde_json::to_string(&keyrings)?;
    Ok(json)
}

pub fn parse(input: &str) -> Result<HashMap<String, Vec<Key>>, Box<dyn std::error::Error>> {
    let pairs = GpgKeyListParser::parse(Rule::keyrings, input)?;
    let mut keyrings: HashMap<String, Vec<Key>> = HashMap::new();

    for pair in pairs {
        if let Rule::keyrings = pair.as_rule() {
            for keyring_pair in pair.into_inner() {
                if let Rule::EOI = keyring_pair.as_rule() {
                    break;
                }

                let keyring = parse_keyring(keyring_pair.to_owned());
                keyrings.insert(keyring.0, keyring.1);
            }
        }
    }

    Ok(keyrings)
}

pub fn parse_keyring(keyring_pair: Pair<'_, Rule>) -> (String, Vec<Key>) {
    let mut path = String::new();
    let mut keys: Vec<Key> = Vec::new();

    for pair in keyring_pair.into_inner() {
        match pair.as_rule() {
            Rule::path => {
                path = pair.as_str().split('\n').collect::<Vec<&str>>()[0]
                    .trim()
                    .to_owned();
            }
            Rule::key => {
                let key = parse_key(pair.to_owned());

                keys.push(key);
            }
            _ => {
                continue;
            }
        };
    }

    (path, keys)
}

pub fn parse_key(key_pair: Pair<'_, Rule>) -> Key {
    let mut key = Key {
        key_type: String::new(),
        created: String::new(),
        can_sign: false,
        can_certify: false,
        can_encrypt: false,
        can_authenticate: false,
        expires: None,
        id: None,
        fingerprint: None,
        trust_level: String::new(),
        real_name: String::new(),
        email: None,
        sub_keys: Vec::new(),
    };

    for pair in key_pair.into_inner() {
        match pair.as_rule() {
            Rule::pub_line => {
                let (
                    key_type,
                    created,
                    can_sign,
                    can_certify,
                    can_encrypt,
                    can_authenticate,
                    expires,
                ) = parse_publine(pair.to_owned());

                key.key_type = key_type;
                key.created = created;
                key.can_sign = can_sign;
                key.can_certify = can_certify;
                key.can_encrypt = can_encrypt;
                key.can_authenticate = can_authenticate;
                key.expires = expires;
            }
            Rule::fingerprint => {
                key.fingerprint = Some(pair.as_str().trim().to_string());
            }
            Rule::uid => {
                let (trust_level, real_name, email) = parse_uid(pair.to_owned());
                key.trust_level = trust_level;
                key.real_name = real_name;
                key.email = email;
            }
            Rule::id => {
                key.id = Some(pair.as_str().trim().to_string());
            }
            Rule::sub_key => {
                let sub_key = parse_sub_key(pair.to_owned());
                key.sub_keys.push(sub_key);
            }
            _ => {
                continue;
            }
        };
    }

    key
}

pub fn parse_publine(
    publine_pair: Pair<'_, Rule>,
) -> (String, String, bool, bool, bool, bool, Option<String>) {
    let mut key_type = String::new();
    let mut created = String::new();
    let mut can_sign = false;
    let mut can_certify = false;
    let mut can_encrypt = false;
    let mut can_authenticate = false;
    let mut expires = None;

    for pair in publine_pair.into_inner() {
        match pair.as_rule() {
            Rule::key_type => {
                key_type = pair.as_str().trim().to_string();
            }
            Rule::created => {
                created = pair.as_str().trim().to_string();
            }
            Rule::capabilities => {
                let capabilities = parse_capabilities(pair.to_owned());
                can_sign = capabilities.0;
                can_certify = capabilities.1;
                can_encrypt = capabilities.2;
                can_authenticate = capabilities.3;
            }
            Rule::expires => {
                expires = parse_expiry(pair.to_owned());
            }
            _ => {
                continue;
            }
        };
    }

    (
        key_type,
        created,
        can_sign,
        can_certify,
        can_encrypt,
        can_authenticate,
        expires,
    )
}

fn parse_expiry(pair: Pair<'_, Rule>) -> Option<String> {
    let expiry = pair.as_str();
    let expiry = &expiry[9..expiry.len() - 1];

    Some(expiry.trim().to_string())
}

fn parse_capabilities(capabilities_pair: Pair<'_, Rule>) -> (bool, bool, bool, bool) {
    let mut can_sign = false;
    let mut can_certify = false;
    let mut can_encrypt = false;
    let mut can_authenticate = false;
    let capabilities = capabilities_pair.as_str();

    if capabilities.contains('S') {
        can_sign = true;
    }

    if capabilities.contains('C') {
        can_certify = true;
    }

    if capabilities.contains('E') {
        can_encrypt = true;
    }

    if capabilities.contains('A') {
        can_authenticate = true;
    }

    (can_sign, can_certify, can_encrypt, can_authenticate)
}

fn parse_uid(uid_pair: Pair<'_, Rule>) -> (String, String, Option<String>) {
    let mut trust_level = String::new();
    let mut real_name = String::new();
    let mut email = None;

    for pair in uid_pair.into_inner() {
        match pair.as_rule() {
            Rule::trust_level => {
                trust_level = pair.as_str().trim().to_string();
            }
            Rule::real_name => {
                real_name = pair.as_str().trim().to_string();
            }
            Rule::email => {
                let _email = pair.as_str();
                let _email = &_email[1.._email.len() - 1];
                let _email = _email.trim();

                email = Some(_email.to_string());
            }
            _ => {
                continue;
            }
        }
    }

    (trust_level, real_name, email)
}

fn parse_sub_key(sub_key_pair: Pair<'_, Rule>) -> SubKey {
    let mut sub_key = SubKey {
        key_type: String::new(),
        created: String::new(),
        can_sign: false,
        can_encrypt: false,
        can_certify: false,
        can_authenticate: false,
        expires: None,
    };

    for pair in sub_key_pair.into_inner() {
        match pair.as_rule() {
            Rule::key_type => {
                sub_key.key_type = pair.as_str().trim().to_string();
            }
            Rule::created => {
                sub_key.created = pair.as_str().trim().to_string();
            }
            Rule::capabilities => {
                let capabilities = parse_capabilities(pair.to_owned());

                sub_key.can_sign = capabilities.0;
                sub_key.can_certify = capabilities.1;
                sub_key.can_encrypt = capabilities.2;
                sub_key.can_authenticate = capabilities.3;
            }
            Rule::expires => {
                sub_key.expires = parse_expiry(pair.to_owned());
            }
            _ => {
                continue;
            }
        };
    }

    sub_key
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    const APT_KEYRINGS: &str = r#"/etc/apt/trusted.gpg
--------------------
pub   rsa4096 2024-04-24 [SC]
      F911 AB18 4317 630C 5997  0973 E363 C90F 8F1B 6217
uid           [ unknown] Launchpad PPA for Ubuntu Git Maintainers

pub   rsa4096 2017-10-23 [SC]
      D89C 66D0 E31F EA28 74EB  D205 6192 2AB6 0068 FCD6
uid           [ unknown] Launchpad PPA for Janek Bevendorff

pub   rsa4096 2015-09-08 [SC]
      EF3F 38C8 FD5E 1EE2 E7B3  B657 6531 2467 9B3C CB19
uid           [ unknown] Launchpad PPA for wereturtle

/etc/apt/trusted.gpg.d/ngrok.asc
--------------------------------
pub   rsa4096 2021-09-18 [SC]
      F027 1FCF 712C F2E3 9901  F1A3 0E61 D3BB AAEE 37FE
uid           [ unknown] ngrok agent apt repo release bot <release-bot@ngrok.com>
sub   rsa4096 2021-09-18 [E]

/etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
------------------------------------------------------
pub   rsa4096 2012-05-11 [SC]
      8439 38DF 228D 22F7 B374  2BC0 D94A A3F0 EFE2 1092
uid           [ unknown] Ubuntu CD Image Automatic Signing Key (2012) <cdimage@ubuntu.com>

/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
------------------------------------------------------
pub   rsa4096 2018-09-17 [SC]
      F6EC B376 2474 EDA9 D21B  7022 8719 20D1 991B C93C
uid           [ unknown] Ubuntu Archive Automatic Signing Key (2018) <ftpmaster@ubuntu.com>

"#;

    const APT_KEYRING: &str = r#"/etc/apt/trusted.gpg
--------------------
pub   rsa4096 2024-04-24 [SC]
      F911 AB18 4317 630C 5997  0973 E363 C90F 8F1B 6217
uid           [ unknown] Launchpad PPA for Ubuntu Git Maintainers

pub   rsa4096 2017-10-23 [SC]
      D89C 66D0 E31F EA28 74EB  D205 6192 2AB6 0068 FCD6
uid           [ unknown] Launchpad PPA for Janek Bevendorff

pub   rsa4096 2015-09-08 [SC]
      EF3F 38C8 FD5E 1EE2 E7B3  B657 6531 2467 9B3C CB19
uid           [ unknown] Launchpad PPA for wereturtle
"#;

    #[test]
    fn test_parse() -> Result<(), Box<dyn Error>> {
        let keyrings = parse(&APT_KEYRINGS.to_string())?;

        assert_eq!(keyrings.keys().len(), 4);

        assert!(keyrings.contains_key("/etc/apt/trusted.gpg"));
        assert!(keyrings.contains_key("/etc/apt/trusted.gpg.d/ngrok.asc"));
        assert!(keyrings.contains_key("/etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg"));
        assert!(keyrings.contains_key("/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg"));
        Ok(())
    }

    #[test]
    fn test_parse_keyring() -> Result<(), Box<dyn Error>> {
        let keyrings = parse(&APT_KEYRING.to_string())?;

        assert_eq!(keyrings.keys().len(), 1);
        assert!(keyrings.contains_key("/etc/apt/trusted.gpg"));

        let keys = keyrings.get("/etc/apt/trusted.gpg").unwrap();

        assert_eq!(keys.len(), 3);

        let expected_keys = vec![
            Key {
                key_type: "rsa4096".to_string(),
                created: "2024-04-24".to_string(),
                can_sign: true,
                can_certify: true,
                can_encrypt: false,
                can_authenticate: false,
                fingerprint: Some("F911 AB18 4317 630C 5997  0973 E363 C90F 8F1B 6217".to_string()),
                id: None,
                expires: None,
                trust_level: "unknown".to_string(),
                real_name: "Launchpad PPA for Ubuntu Git Maintainers".to_string(),
                email: None,
                sub_keys: Vec::new(),
            },
            Key {
                key_type: "rsa4096".to_string(),
                created: "2017-10-23".to_string(),
                can_sign: true,
                can_certify: true,
                can_encrypt: false,
                can_authenticate: false,
                fingerprint: Some("D89C 66D0 E31F EA28 74EB  D205 6192 2AB6 0068 FCD6".to_string()),
                id: None,
                expires: None,
                trust_level: "unknown".to_string(),
                real_name: "Launchpad PPA for Janek Bevendorff".to_string(),
                email: None,
                sub_keys: Vec::new(),
            },
            Key {
                key_type: "rsa4096".to_string(),
                created: "2015-09-08".to_string(),
                can_sign: true,
                can_certify: true,
                can_encrypt: false,
                can_authenticate: false,
                fingerprint: Some("EF3F 38C8 FD5E 1EE2 E7B3  B657 6531 2467 9B3C CB19".to_string()),
                id: None,
                expires: None,
                trust_level: "unknown".to_string(),
                real_name: "Launchpad PPA for wereturtle".to_string(),
                email: None,
                sub_keys: Vec::new(),
            },
        ];

        for i in 0..keys.len() {
            assert_eq!(keys[i].key_type, expected_keys[i].key_type);
            assert_eq!(keys[i].created, expected_keys[i].created);
            assert_eq!(keys[i].can_sign, expected_keys[i].can_sign);
            assert_eq!(keys[i].can_certify, expected_keys[i].can_certify);
            assert_eq!(keys[i].can_encrypt, expected_keys[i].can_encrypt);
            assert_eq!(keys[i].can_authenticate, expected_keys[i].can_authenticate);
            assert_eq!(keys[i].fingerprint, expected_keys[i].fingerprint);
            assert_eq!(keys[i].id, expected_keys[i].id);
            assert_eq!(keys[i].expires, expected_keys[i].expires);
            assert_eq!(keys[i].trust_level, expected_keys[i].trust_level);
            assert_eq!(keys[i].real_name, expected_keys[i].real_name);
            assert_eq!(keys[i].email, expected_keys[i].email);

            let sub_keys = &keys[i].sub_keys;
            let expected_sub_keys = &expected_keys[i].sub_keys;

            for j in 0..sub_keys.len() {
                assert_eq!(sub_keys[j].key_type, expected_sub_keys[j].key_type);
                assert_eq!(sub_keys[j].created, expected_sub_keys[j].created);
                assert_eq!(sub_keys[j].can_sign, expected_sub_keys[j].can_sign);
                assert_eq!(sub_keys[j].can_certify, expected_sub_keys[j].can_certify);
                assert_eq!(sub_keys[j].can_encrypt, expected_sub_keys[j].can_encrypt);
                assert_eq!(sub_keys[j].expires, expected_sub_keys[j].expires);
            }
        }

        Ok(())
    }

    #[test]
    fn test_parse_key() -> Result<(), Box<dyn Error>> {
        let pairs = GpgKeyListParser::parse(
            Rule::key,
            r#"pub   rsa3072 2025-08-13 [SCE] [expires: 2027-08-13]
      A6C4C64CCC8E8D4A278660B0A78A721FDBC087D9
uid           [ultimate] testing <testing@local>
sub   rsa4096 2025-08-13 [S]
sub   rsa4096 2025-08-13 [A]
sub   rsa4096 2025-08-13 [E]
"#,
        )?;

        let expected_key = Key {
            key_type: "rsa3072".to_string(),
            created: "2025-08-13".to_string(),
            can_sign: true,
            can_certify: true,
            can_encrypt: true,
            can_authenticate: false,
            fingerprint: None,
            id: Some("A6C4C64CCC8E8D4A278660B0A78A721FDBC087D9".to_string()),
            expires: Some("2027-08-13".to_string()),
            trust_level: "ultimate".to_string(),
            real_name: "testing".to_string(),
            email: Some("testing@local".to_string()),
            sub_keys: vec![
                SubKey {
                    key_type: "rsa4096".to_string(),
                    created: "2025-08-13".to_string(),
                    expires: None,
                    can_sign: true,
                    can_certify: false,
                    can_encrypt: false,
                    can_authenticate: false,
                },
                SubKey {
                    key_type: "rsa4096".to_string(),
                    created: "2025-08-13".to_string(),
                    expires: None,
                    can_sign: false,
                    can_certify: false,
                    can_encrypt: false,
                    can_authenticate: true,
                },
                SubKey {
                    key_type: "rsa4096".to_string(),
                    created: "2025-08-13".to_string(),
                    expires: None,
                    can_sign: false,
                    can_certify: false,
                    can_encrypt: true,
                    can_authenticate: false,
                },
            ],
        };

        for p in pairs {
            if let Rule::key = p.as_rule() {
                let key = parse_key(p);

                assert_eq!(key.key_type, expected_key.key_type);
                assert_eq!(key.created, expected_key.created);
                assert_eq!(key.can_sign, expected_key.can_sign);
                assert_eq!(key.can_certify, expected_key.can_certify);
                assert_eq!(key.can_encrypt, expected_key.can_encrypt);
                assert_eq!(key.can_authenticate, expected_key.can_authenticate);
                assert_eq!(key.fingerprint, expected_key.fingerprint);
                assert_eq!(key.id, expected_key.id);
                assert_eq!(key.expires, expected_key.expires);
                assert_eq!(key.trust_level, expected_key.trust_level);
                assert_eq!(key.real_name, expected_key.real_name);
                assert_eq!(key.email, expected_key.email);

                let sub_keys = &key.sub_keys;

                for j in 0..sub_keys.len() {
                    assert_eq!(sub_keys[j].key_type, expected_key.sub_keys[j].key_type);
                    assert_eq!(sub_keys[j].created, expected_key.sub_keys[j].created);
                    assert_eq!(sub_keys[j].can_sign, expected_key.sub_keys[j].can_sign);
                    assert_eq!(
                        sub_keys[j].can_certify,
                        expected_key.sub_keys[j].can_certify
                    );
                    assert_eq!(
                        sub_keys[j].can_encrypt,
                        expected_key.sub_keys[j].can_encrypt
                    );
                    assert_eq!(sub_keys[j].expires, expected_key.sub_keys[j].expires);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_parse_publine() -> Result<(), Box<dyn Error>> {
        let pairs = GpgKeyListParser::parse(
            Rule::pub_line,
            "pub   rsa3072 2025-08-13 [SCE] [expires: 2027-08-13]",
        )?;

        for p in pairs {
            if let Rule::pub_line = p.as_rule() {
                let pub_line = parse_publine(p);

                assert_eq!(pub_line.0, "rsa3072".to_string());
                assert_eq!(pub_line.1, "2025-08-13".to_string());
                assert_eq!(pub_line.2, true);
                assert_eq!(pub_line.3, true);
                assert_eq!(pub_line.4, true);
                assert_eq!(pub_line.5, false);
                assert_eq!(pub_line.6, Some("2027-08-13".to_string()));
            }
        }

        Ok(())
    }

    #[test]
    fn test_parse_expiry() -> Result<(), Box<dyn Error>> {
        let pairs = GpgKeyListParser::parse(
            Rule::expires,
            "[expires: 2027-08-13]
",
        )?;

        for p in pairs {
            if let Rule::expires = p.as_rule() {
                let expires = parse_expiry(p);
                assert_eq!(expires, Some("2027-08-13".to_string()));
            }
        }

        Ok(())
    }

    #[test]
    fn test_parse_capabilities() -> Result<(), Box<dyn Error>> {
        let pairs = GpgKeyListParser::parse(Rule::capabilities, "[SCE]")?;

        for p in pairs {
            if let Rule::capabilities = p.as_rule() {
                let (sign, certify, enc, auth) = parse_capabilities(p);

                assert!(sign);
                assert!(certify);
                assert!(enc);
                assert!(!auth);
            }
        }

        Ok(())
    }

    #[test]
    fn test_parse_uid() -> Result<(), Box<dyn Error>> {
        let pairs = GpgKeyListParser::parse(
            Rule::uid,
            "uid           [ultimate] testing <testing@local>
",
        )?;

        for p in pairs {
            if let Rule::uid = p.as_rule() {
                let (trust, real_name, email) = parse_uid(p);
                assert_eq!(trust, "ultimate".to_string());
                assert_eq!(real_name, "testing".to_string());
                assert_eq!(email, Some("testing@local".to_string()));
            }
        }

        Ok(())
    }

    #[test]
    fn test_parse_sub_key() -> Result<(), Box<dyn Error>> {
        let pairs = GpgKeyListParser::parse(
            Rule::sub_key,
            "sub   rsa3072 2025-08-13 [E] [expires: 2027-08-13]
",
        )?;

        for p in pairs {
            if let Rule::sub_key = p.as_rule() {
                let key = parse_sub_key(p);

                assert_eq!(key.key_type, "rsa3072".to_string());
                assert_eq!(key.created, "2025-08-13".to_string());
                assert!(!key.can_sign);
                assert!(!key.can_certify);
                assert!(key.can_encrypt);
                assert_eq!(key.expires, Some("2027-08-13".to_string()));
            }
        }

        Ok(())
    }
}
