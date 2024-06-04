
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::{Object, ToJson};
use identity_iota::credential::{DecodedJwtCredential, FailFast, JwtCredentialValidationOptions, JwtCredentialValidator, JwtCredentialValidatorUtils};
use identity_iota::iota::{IotaDID, IotaDocument, IotaIdentityClientExt};
use iota_sdk::client::Client;
use demo10maggio::utils::API_ENDPOINT;
use demo10maggio::identitylib::{ get_blocklist, get_vc_from_block};
use serde_json::Value;


#[tokio::main]
async fn main() -> anyhow::Result<()> {

    //configurazione dati
    let client: Client = Client::builder()
        .with_primary_node(API_ENDPOINT, None)?
        .finish()
        .await?;
    
    let file: &str = "/home/sallevi/Scrivania/demo10maggio/blocks/atti_notarili";

    //recuper del blocco e della vc
    println!("Recupero vc per gli atti notarili... ");
    let blocklist = get_blocklist(file).await?;
    
    let last_block = blocklist.last().unwrap();

    let last_cred = get_vc_from_block(&last_block, &client).await?;

    let issuer_did: IotaDID = JwtCredentialValidatorUtils::extract_issuer_from_jwt(&last_cred)?;

    let issuer_document: IotaDocument = client.resolve_did(&issuer_did).await?;

    //verifica della vc e decodifica
    let decoded_credential: DecodedJwtCredential<Object> =
    JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
      .validate::<_, Object>(
        &last_cred,
        &issuer_document,
        &JwtCredentialValidationOptions::default(),
        FailFast::FirstError,
      )
      .unwrap();

    println!("Credential JSON > {:#}", decoded_credential.credential);

    let cred = decoded_credential.credential;
    let cred_sub = cred.credential_subject;

    //estrazione dell'hash dalla vc
    let cred_sub_json = cred_sub.to_json().unwrap();

    let data: Value = serde_json::from_str(&cred_sub_json).unwrap();

    // Estrarre il campo "filehash" all'interno del campo "documentdata"
    let doc_hash = data["DocumentData"]["fileHash"].as_str().unwrap();

    println!("L'hash del documento richiesto è : {}", doc_hash);
    Ok(())

}