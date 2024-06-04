use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;

use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Object;
use identity_iota::credential::{DecodedJwtCredential, FailFast, JwtCredentialValidationOptions, JwtCredentialValidator};
use identity_iota::iota::{IotaDID, IotaDocument, IotaIdentityClientExt};
use iota_sdk::client::Client;
use demo10maggio::utils::API_ENDPOINT;
use demo10maggio::identitylib::{ create_vc_atto, get_issuer_storage, push_block, write_block};
use serde::{Deserialize, Serialize};
use sha256::digest;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    did_holder_string: String,
    did_issuer_string: String,
    fragment: String,
    password: String,
    stronghold_path: String,
    file_path: String,
    tag_str: String,
    filename: String
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let config_path = "/home/sallevi/Scrivania/demo10maggio/config.json";

    // Leggi il contenuto del file JSON
    let mut file = File::open(config_path).expect("Impossibile aprire il file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Impossibile leggere il file");

    // Deserializza il contenuto JSON nella struttura Config
    let config: Config = serde_json::from_str(&contents).expect("Errore nella deserializzazione JSON");

    //Config dati
    let did_string = config.did_holder_string;
    let did_issuer_string = config.did_issuer_string;
    let fragment = config.fragment;
    let password = config.password;
    let stronghold_path = config.stronghold_path;
    let file_path= config.file_path;
    let tag_str = &config.tag_str;
    let filename = &config.filename;

    let client: Client = Client::builder()
        .with_primary_node(API_ENDPOINT, None)?
        .finish()
        .await?;

    let did_holder: IotaDID = IotaDID::parse(did_string).unwrap();
    let did_iss = IotaDID::parse(did_issuer_string).unwrap();

    let storage = get_issuer_storage(&stronghold_path, &password).await?;

    let holder_document: IotaDocument = client.resolve_did(&did_holder).await?;
    let issuer_document: IotaDocument = client.resolve_did(&did_iss).await?;

    //Lettura file
    let mut file = File::open(file_path).expect("impossibile aprire il file");
    let mut content = Vec::new();
    file.read_to_end(&mut content).expect("Impossibile leggere file");

    let hash = digest(content);

    let credential_jwt = create_vc_atto(&storage,&fragment,&issuer_document,&holder_document,&hash).await?;

    let decoded_credential: DecodedJwtCredential<Object> =
          JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
            .validate::<_, Object>(
              &credential_jwt,
              &issuer_document,
              &JwtCredentialValidationOptions::default(),
              FailFast::FirstError,
            )
            .unwrap();

    println!("VC successfully validated");

    println!("Credential JSON > {:#}", decoded_credential.credential);


    let blockid = push_block(tag_str, &credential_jwt, &client).await?;

    let ok = write_block(filename, &blockid).await?;

    Ok(())

}