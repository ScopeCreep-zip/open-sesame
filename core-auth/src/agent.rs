//! SSH agent client for the two requests vault unlock makes: listing the
//! agent's identities and asking it to sign (draft-ietf-sshm-ssh-agent-16
//! §3.5, §3.6; message numbers and flags §6).
//!
//! Every message is `uint32 length || byte type || contents` (§3). The
//! agent holds the private keys; this client parses public key blobs and
//! verifies each signature against the key it names before key material
//! is derived from it. Agents are reached over Unix domain sockets (§4);
//! Windows named pipes are not supported.

use std::io::{Read, Write};
use std::path::Path;

use crate::AuthError;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// `SSH_AGENT_RSA_SHA2_512` (§3.6.1, §6.3): RSA keys sign with `rsa-sha2-512`.
/// SSH enrollment KEKs derive from these signatures, so the flag is part
/// of the enrollment format: another hash would not reproduce the KEK.
const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// Largest agent reply read; a reply announcing more is a protocol error.
const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// Most identities accepted in one answer.
const MAX_IDENTITIES: usize = 1024;

/// Suffix of OpenSSH certificate key types.
const CERT_SUFFIX: &str = "-cert-v01@openssh.com";

/// A key the agent holds.
#[derive(Debug, Clone)]
pub(crate) struct Identity {
    /// The key blob exactly as the agent listed it; sign requests name the
    /// key with these bytes.
    blob: Vec<u8>,
    /// The public key: the key itself, or the key a certificate carries.
    key: ssh_key::public::KeyData,
    comment: String,
}

impl Identity {
    /// `SHA256:` fingerprint of the public key.
    pub(crate) fn fingerprint(&self) -> String {
        self.key.fingerprint(ssh_key::HashAlg::Sha256).to_string()
    }

    pub(crate) fn algorithm(&self) -> ssh_key::Algorithm {
        self.key.algorithm()
    }

    pub(crate) fn comment(&self) -> &str {
        &self.comment
    }

    /// The signature algorithm this identity's signatures must carry:
    /// `rsa-sha2-512` for RSA keys (the sign request asks for it, and SSH
    /// enrollment KEKs derive from it), the key's own algorithm otherwise.
    fn signature_algorithm(&self) -> ssh_key::Algorithm {
        match self.algorithm() {
            ssh_key::Algorithm::Rsa { .. } => ssh_key::Algorithm::Rsa {
                hash: Some(ssh_key::HashAlg::Sha512),
            },
            other => other,
        }
    }

    /// Accept `signature` of `data` only when it carries this identity's
    /// signature algorithm and verifies against its public key.
    fn verify(&self, data: &[u8], signature: &ssh_key::Signature) -> Result<(), AuthError> {
        let expected = self.signature_algorithm();
        if signature.algorithm() != expected {
            return Err(protocol(format!(
                "the agent signed with {}, not {expected}",
                signature.algorithm()
            )));
        }
        signature::Verifier::verify(&self.key, data, signature).map_err(|e| {
            protocol(format!(
                "the agent's signature does not verify against {}: {e}",
                self.fingerprint()
            ))
        })
    }

    /// Parse one listed identity: an OpenSSH certificate when its key type
    /// ends in `-cert-v01@openssh.com`, otherwise a public key.
    fn parse(blob: Vec<u8>, comment: String) -> Result<Self, AuthError> {
        let mut reader = blob.as_slice();
        let key_type = std::str::from_utf8(take_string(&mut reader)?)
            .map_err(|e| protocol(format!("identity key type is not UTF-8: {e}")))?;
        let key = if key_type.ends_with(CERT_SUFFIX) {
            ssh_key::Certificate::from_bytes(&blob)
                .map_err(|e| protocol(format!("identity certificate {key_type}: {e}")))?
                .public_key()
                .clone()
        } else {
            ssh_key::PublicKey::from_bytes(&blob)
                .map_err(|e| protocol(format!("identity key {key_type}: {e}")))?
                .key_data()
                .clone()
        };
        Ok(Self { blob, key, comment })
    }
}

/// A connection to one agent.
pub(crate) struct Agent<S> {
    stream: S,
}

impl Agent<std::os::unix::net::UnixStream> {
    /// Connect to the agent socket at `path`.
    pub(crate) fn connect(path: &Path) -> std::io::Result<Self> {
        Ok(Self::new(std::os::unix::net::UnixStream::connect(path)?))
    }
}

impl<S: Read + Write> Agent<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self { stream }
    }

    /// The identities the agent holds, in agent order.
    ///
    /// # Errors
    ///
    /// `AuthError::AgentProtocolError` for a transport failure, a reply
    /// other than `SSH_AGENT_IDENTITIES_ANSWER`, or a malformed answer.
    pub(crate) fn identities(&mut self) -> Result<Vec<Identity>, AuthError> {
        self.send(SSH_AGENTC_REQUEST_IDENTITIES, &[])?;
        let (kind, body) = self.receive()?;
        if kind != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(protocol(format!(
                "identity request answered with message type {kind}"
            )));
        }
        let mut reader = body.as_slice();
        let count = usize::try_from(take_u32(&mut reader)?)
            .map_err(|_| protocol("identity count overflows usize".into()))?;
        if count > MAX_IDENTITIES {
            return Err(protocol(format!(
                "agent lists {count} identities, more than {MAX_IDENTITIES}"
            )));
        }
        let mut identities = Vec::with_capacity(count);
        for _ in 0..count {
            let blob = take_string(&mut reader)?.to_vec();
            let comment = String::from_utf8(take_string(&mut reader)?.to_vec())
                .map_err(|e| protocol(format!("identity comment is not UTF-8: {e}")))?;
            identities.push(Identity::parse(blob, comment)?);
        }
        if !reader.is_empty() {
            return Err(protocol(format!(
                "{} bytes follow the last identity",
                reader.len()
            )));
        }
        Ok(identities)
    }

    /// Ask the agent to sign `data` with `identity`; returns the raw
    /// signature bytes (the algorithm-specific value inside the signature
    /// blob) once the signature verifies against the identity's key. RSA
    /// keys are asked for `rsa-sha2-512`.
    ///
    /// # Errors
    ///
    /// `AuthError::AgentProtocolError` when the agent refuses
    /// (`SSH_AGENT_FAILURE`: key absent, confirmation declined, flags
    /// unsupported), for a transport failure, for a malformed reply, or for
    /// a signature of another algorithm or one that does not verify.
    pub(crate) fn sign(&mut self, identity: &Identity, data: &[u8]) -> Result<Vec<u8>, AuthError> {
        let flags = if identity.algorithm().is_rsa() {
            SSH_AGENT_RSA_SHA2_512
        } else {
            0
        };
        let mut request = Vec::with_capacity(4 + identity.blob.len() + 4 + data.len() + 4);
        put_string(&mut request, &identity.blob)?;
        put_string(&mut request, data)?;
        request.extend_from_slice(&flags.to_be_bytes());
        self.send(SSH_AGENTC_SIGN_REQUEST, &request)?;

        let (kind, body) = self.receive()?;
        match kind {
            SSH_AGENT_SIGN_RESPONSE => {
                let mut reader = body.as_slice();
                let blob = take_string(&mut reader)?;
                if !reader.is_empty() {
                    return Err(protocol(format!(
                        "{} bytes follow the signature",
                        reader.len()
                    )));
                }
                let signature = ssh_key::Signature::try_from(blob)
                    .map_err(|e| protocol(format!("signature blob: {e}")))?;
                identity.verify(data, &signature)?;
                Ok(signature.as_bytes().to_vec())
            }
            SSH_AGENT_FAILURE => Err(protocol("the agent refused to sign".into())),
            other => Err(protocol(format!(
                "sign request answered with message type {other}"
            ))),
        }
    }

    /// Write one message: `uint32 length || byte kind || contents`.
    fn send(&mut self, kind: u8, contents: &[u8]) -> Result<(), AuthError> {
        let len = u32::try_from(contents.len() + 1)
            .map_err(|_| protocol(format!("request of {} bytes", contents.len())))?;
        let mut message = Vec::with_capacity(4 + 1 + contents.len());
        message.extend_from_slice(&len.to_be_bytes());
        message.push(kind);
        message.extend_from_slice(contents);
        self.stream
            .write_all(&message)
            .and_then(|()| self.stream.flush())
            .map_err(|e| protocol(format!("write to agent: {e}")))
    }

    /// Read one message; returns its type and contents.
    fn receive(&mut self) -> Result<(u8, Vec<u8>), AuthError> {
        let mut len = [0u8; 4];
        self.stream
            .read_exact(&mut len)
            .map_err(|e| protocol(format!("read reply length: {e}")))?;
        let len = usize::try_from(u32::from_be_bytes(len))
            .map_err(|_| protocol("reply length overflows usize".into()))?;
        if len == 0 || len > MAX_MESSAGE_LEN {
            return Err(protocol(format!(
                "reply length {len} outside 1..={MAX_MESSAGE_LEN}"
            )));
        }
        let mut message = vec![0u8; len];
        self.stream
            .read_exact(&mut message)
            .map_err(|e| protocol(format!("read reply of {len} bytes: {e}")))?;
        let contents = message.split_off(1);
        Ok((message[0], contents))
    }
}

fn protocol(message: String) -> AuthError {
    AuthError::AgentProtocolError(message)
}

/// Read a `uint32` (RFC 4251 §5).
fn take_u32(reader: &mut &[u8]) -> Result<u32, AuthError> {
    let Some((head, rest)) = reader.split_first_chunk::<4>() else {
        return Err(protocol(format!(
            "uint32 needs 4 bytes, {} remain",
            reader.len()
        )));
    };
    *reader = rest;
    Ok(u32::from_be_bytes(*head))
}

/// Read a `string`: a `uint32` length and that many bytes (RFC 4251 §5).
fn take_string<'a>(reader: &mut &'a [u8]) -> Result<&'a [u8], AuthError> {
    let len = usize::try_from(take_u32(reader)?)
        .map_err(|_| protocol("string length overflows usize".into()))?;
    if len > reader.len() {
        return Err(protocol(format!(
            "string of {len} bytes, {} remain",
            reader.len()
        )));
    }
    let (value, rest) = reader.split_at(len);
    *reader = rest;
    Ok(value)
}

/// Append a `string` (RFC 4251 §5).
fn put_string(out: &mut Vec<u8>, value: &[u8]) -> Result<(), AuthError> {
    let len = u32::try_from(value.len())
        .map_err(|_| protocol(format!("string of {} bytes", value.len())))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    const ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.invalid";
    /// ssh-key 0.6.7's own 3072-bit RSA example key (`tests/examples/id_rsa_3072.pub`).
    const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmjkeMm8k3JkNrf16eb5pG4bc77B6Mt3VN4saltsRV8vASpyWa/PlBgdaeldOaNJ5NK0gqU3KyiUNzHbdcc8572e7IUBDJS/rlaWARiSL4aos2VbNX0k56Z5zYp9m/bq5m9/mlb+PQkNBjIhimgpYNiq2TwBiYeA6tLb79cPtHA0cX5BLk/a5oUpLsiR4kI/f+Q98vVDKasKXXVh5YLkLobrruDB6er2A9fOcIUF0O4JCRLh/Dc161gE3fQrYTMQenbppZzfxrZfQ8YwLPvKjnqm+XRX+pbTtaJuj0EgTSzUK+EZxoSw8CNwiZpxrjwecTMVQ8w/srQmh4ABGuTqk0wP8HcI7hg+fpBv7kiejh5X/Oehxt+Puu85u9GVXb1a0av/vhJvUCBcuISvCA/z1wVJ0xdLhb1/ZiTDdTzyNbZQ0OQijzK+e1SlkNhp+3eGVZu3pNZvnTppwIXv3wg6kV1HodkWGgh1ayY7Buc52Z8okDYqvJat5CzOj5OaQNr/k= user@example.com";

    fn key_blob(openssh: &str) -> Vec<u8> {
        ssh_key::PublicKey::from_openssh(openssh)
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    fn message(kind: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&u32::try_from(contents.len() + 1).unwrap().to_be_bytes());
        out.push(kind);
        out.extend_from_slice(contents);
        out
    }

    fn string(value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, value).unwrap();
        out
    }

    /// Run `agent` on the far end of a socket pair: it reads one request
    /// message and answers with `reply`; the request is returned.
    fn serve_one(reply: Vec<u8>) -> (Agent<UnixStream>, std::thread::JoinHandle<Vec<u8>>) {
        let (client, mut server) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            server.read_exact(&mut len).unwrap();
            let mut request = vec![0u8; u32::from_be_bytes(len) as usize];
            server.read_exact(&mut request).unwrap();
            server.write_all(&reply).unwrap();
            request
        });
        (Agent::new(client), handle)
    }

    fn identities_answer(keys: &[(&[u8], &str)]) -> Vec<u8> {
        let mut contents = u32::try_from(keys.len()).unwrap().to_be_bytes().to_vec();
        for (blob, comment) in keys {
            contents.extend(string(blob));
            contents.extend(string(comment.as_bytes()));
        }
        message(SSH_AGENT_IDENTITIES_ANSWER, &contents)
    }

    #[test]
    fn identities_are_parsed_with_comments_and_fingerprints() {
        let blob = key_blob(ED25519);
        let (mut agent, server) = serve_one(identities_answer(&[(&blob, "alice@laptop")]));
        let identities = agent.identities().unwrap();
        assert_eq!(server.join().unwrap(), [SSH_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].comment(), "alice@laptop");
        assert_eq!(identities[0].algorithm(), ssh_key::Algorithm::Ed25519);
        let expected = ssh_key::PublicKey::from_openssh(ED25519)
            .unwrap()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        assert_eq!(identities[0].fingerprint(), expected);
    }

    /// The deterministic Ed25519 key of `seed`, as the test agent holds it.
    fn ed25519_key(seed: u8) -> ssh_key::PrivateKey {
        ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn identity_of(key: &ssh_key::PrivateKey) -> Identity {
        Identity::parse(key.public_key().to_bytes().unwrap(), String::new()).unwrap()
    }

    /// The agent's answer carrying the signature blob `signature`.
    fn sign_response(signature: &[u8]) -> Vec<u8> {
        message(SSH_AGENT_SIGN_RESPONSE, &string(signature))
    }

    /// A signature blob of `algorithm` over the raw bytes `data`.
    fn forged(algorithm: &[u8], data: &[u8]) -> Vec<u8> {
        let mut blob = string(algorithm);
        blob.extend(string(data));
        blob
    }

    #[test]
    fn rsa_sign_requests_ask_for_sha2_512_and_echo_the_listed_blob() {
        let identity = Identity::parse(key_blob(RSA), String::new()).unwrap();
        let (mut agent, server) = serve_one(sign_response(&forged(b"rsa-sha2-512", &[0x5A; 384])));
        let err = agent.sign(&identity, b"challenge").unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");

        let request = server.join().unwrap();
        let mut expected = vec![SSH_AGENTC_SIGN_REQUEST];
        expected.extend(string(&identity.blob));
        expected.extend(string(b"challenge"));
        expected.extend(SSH_AGENT_RSA_SHA2_512.to_be_bytes());
        assert_eq!(request, expected);
    }

    #[test]
    fn an_rsa_signature_other_than_sha2_512_is_rejected() {
        let identity = Identity::parse(key_blob(RSA), String::new()).unwrap();
        let (mut agent, server) = serve_one(sign_response(&forged(b"rsa-sha2-256", &[0x5A; 384])));
        let err = agent.sign(&identity, b"challenge").unwrap_err();
        server.join().unwrap();
        assert!(err.to_string().contains("not rsa-sha2-512"), "{err}");
    }

    #[test]
    fn a_verified_ed25519_signature_is_returned_and_its_request_carries_no_flags() {
        let key = ed25519_key(7);
        let signature: ssh_key::Signature = signature::Signer::try_sign(&key, b"c").unwrap();
        let blob = ssh_key::encoding::Encode::encode_vec(&signature).unwrap();
        let (mut agent, server) = serve_one(sign_response(&blob));
        assert_eq!(
            agent.sign(&identity_of(&key), b"c").unwrap(),
            signature.as_bytes()
        );
        let request = server.join().unwrap();
        assert_eq!(request[request.len() - 4..], [0, 0, 0, 0]);
    }

    #[test]
    fn a_signature_that_does_not_verify_is_rejected() {
        let key = ed25519_key(7);
        // Another key's signature, and this key's signature over other data.
        let other: ssh_key::Signature = signature::Signer::try_sign(&ed25519_key(8), b"c").unwrap();
        let elsewhere: ssh_key::Signature = signature::Signer::try_sign(&key, b"d").unwrap();
        for signature in [other, elsewhere] {
            let blob = ssh_key::encoding::Encode::encode_vec(&signature).unwrap();
            let (mut agent, server) = serve_one(sign_response(&blob));
            let err = agent.sign(&identity_of(&key), b"c").unwrap_err();
            server.join().unwrap();
            assert!(err.to_string().contains("does not verify"), "{err}");
        }
        // A forged blob of the right algorithm.
        let (mut agent, server) = serve_one(sign_response(&forged(b"ssh-ed25519", &[0x11; 64])));
        assert!(agent.sign(&identity_of(&key), b"c").is_err());
        server.join().unwrap();
    }

    #[test]
    fn a_refused_signature_is_an_error() {
        let identity = Identity::parse(key_blob(ED25519), String::new()).unwrap();
        let (mut agent, server) = serve_one(message(SSH_AGENT_FAILURE, &[]));
        let err = agent.sign(&identity, b"c").unwrap_err();
        server.join().unwrap();
        assert!(err.to_string().contains("refused"), "{err}");
    }

    #[test]
    fn malformed_answers_are_rejected() {
        // More identities than the bound.
        let mut contents = u32::try_from(MAX_IDENTITIES + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        contents.extend([0; 4]);
        let (mut agent, server) = serve_one(message(SSH_AGENT_IDENTITIES_ANSWER, &contents));
        assert!(agent.identities().is_err());
        server.join().unwrap();

        // A key blob longer than the message.
        let mut contents = 1u32.to_be_bytes().to_vec();
        contents.extend(0x100u32.to_be_bytes());
        let (mut agent, server) = serve_one(message(SSH_AGENT_IDENTITIES_ANSWER, &contents));
        assert!(agent.identities().is_err());
        server.join().unwrap();

        // An oversized reply length.
        let reply = u32::try_from(MAX_MESSAGE_LEN + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        let (mut agent, server) = serve_one(reply);
        assert!(agent.identities().is_err());
        server.join().unwrap();

        // The wrong reply type.
        let (mut agent, server) = serve_one(message(SSH_AGENT_SIGN_RESPONSE, &[]));
        assert!(agent.identities().is_err());
        server.join().unwrap();
    }
}
