use std::{fs::{File, OpenOptions}, io::{self, BufRead, Write}, path::PathBuf, str::FromStr};


use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::{core::{FromJson, Object, Timestamp, ToJson, Url}, credential::{Credential, CredentialBuilder, DecodedJwtCredential, DecodedJwtPresentation, FailFast, Jwt, JwtCredentialValidationOptions, JwtCredentialValidator, JwtPresentationOptions, JwtPresentationValidationOptions, JwtPresentationValidator, JwtPresentationValidatorUtils, Presentation, PresentationBuilder, Subject}, did::{CoreDID, DID}, document::verifiable::JwsVerificationOptions, iota::{IotaClientExt, IotaDocument, IotaIdentityClientExt, NetworkName}, resolver::Resolver, verification::{jws::JwsAlgorithm, MethodScope}};
use identity_iota::prelude::IotaDID;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_storage::{JwkDocumentExt, JwkMemStore, JwsSignatureOptions, Storage};
use identity_stronghold::StrongholdStorage;
use iota_sdk::{client::{secret::stronghold::StrongholdSecretManager, Client, Password}, types::block::{address::Address, output::AliasOutput, payload::Payload, BlockId}};
use serde_json::{json, Value};

use crate::utils::get_address_with_funds;


///Generates a DID from the given client and stronghold storage, 
///giving back the address, the DID document, and the fragment
/// 
/// 
/// # Arguments
/// 
/// * 'client': an IOTA node client.
/// * 'stronghold_storage': a storage that creates internally a 'secretManager' that 
///                         can be referenced to avoid creating multiple instances around the 
///                         same stronghold snapshot.
/// 
/// # Returns
/// 
/// * 'address': the address of the holder
/// * 'iotadocument': the did document of the did holder
/// * 'fragment': a string that is nedeed in order to sign Vc
pub async fn create_did(
    client: &Client,
    stronghold_storage: &StrongholdStorage
  ) -> anyhow::Result<(Address, IotaDocument, String)> {

    let faucet_endpoint: &str = "http://localhost/faucet/api/enqueue";

    let address: Address = get_address_with_funds(&client, stronghold_storage.as_secret_manager(), faucet_endpoint).await?;

    // Get the Bech32 human-readable part (HRP) of the network.
    let network_name: NetworkName = client.network_name().await?;

    // Create a new DID document with a placeholder DID.
    // The DID will be derived from the Alias Id of the Alias Output after publishing.
    let mut document: IotaDocument = IotaDocument::new(&network_name);

    let storage = Storage::new(stronghold_storage.clone(), stronghold_storage.clone());

    let fragment =document
    .generate_method(
    &storage,
    JwkMemStore::ED25519_KEY_TYPE,
    JwsAlgorithm::EdDSA,
    None,
    MethodScope::VerificationMethod,
    )
    .await?;

    // Construct an Alias Output containing the DID document, with the wallet address
    // set as both the state controller and governor.
    let alias_output: AliasOutput = client.new_did_output(address, document, None).await?;

    // Publish the Alias Output and get the published DID document.
    let document: IotaDocument = client.publish_did_output(stronghold_storage.as_secret_manager(), alias_output).await?;
    
    Ok((address, document, fragment))
}

///Generates a Vc from the given issuer and holder information,
///  a credential as jwt is returned upon success
/// 
/// # Arguments
/// 
/// * 'storage': the storage that keeps the issuer information in order to sign jwt
/// * 'fragment': a string associeted with the DID verification method, for the signing of Vc
/// * 'issuer_doc': the IotaDocument issuer document
/// * 'holder_doc': the IotaDocument holder document
/// 
/// # Returns
/// 
/// * 'credential': The credential generated as Jwt
pub async fn create_vc(
    storage: &Storage<StrongholdStorage, StrongholdStorage>,
    fragment: &str,
    issuer_doc: &IotaDocument,
    holder_doc: &IotaDocument
) -> anyhow::Result<Jwt> {

    //Create a credential subject
    let subject: Subject = Subject::from_json_value(json!({
        "holder": holder_doc.id().as_str(),
        "ChainData": {
          "id": "a9826734-cbce-5aa0-5f98-605d303a0750",
          "assetData": {
            "GS1:functionalName": "Carbon dioxide",
            "GS1:country": "Spain"
          },
          "previousCredential": null,
          
        },
      }))?;

      //Build credential using subject above and issuer
      let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_doc.id().as_str())?)
    .type_("BCVerifiableSupplyChainCredential")
    .type_("AssetDataStandard")
    .subject(subject)
    .build()?;

    let credential_jwt: Jwt = issuer_doc
    .create_credential_jwt(
      &credential,
      &storage,
      &fragment,
      &JwsSignatureOptions::default(),
      None,
    )
    .await?;

    Ok(credential_jwt)
}

/// Generates a Vc from the given holder information and block_id of the previous Vc,
///     a credential as Jwt is returned upon success.
/// 
/// # Arguments
/// 
/// * 'storage': the storage that keeps the issuer information in order to sign jwt
/// * 'fragment': a string associeted with the DID verification method, for the signing of Vc
/// * 'issuer_doc': the IotaDocument issuer document
/// * 'holder_doc': the IotaDocument holder document
/// * 'block_id': the block_id of the previous Vc
/// 
/// # Returns
/// 
/// * 'credential': the credential generated as Jwt 
pub async fn create_vc_blockid(
    storage: &Storage<StrongholdStorage, StrongholdStorage>,
    fragment: &str,
    issuer_doc: &IotaDocument,
    holder_doc: &IotaDocument,
    block_id: &BlockId
) -> anyhow::Result<Jwt> {
    let subject: Subject = Subject::from_json_value(json!({
        "holder": holder_doc.id().as_str(),
        "ChainData": {
          "id": "a9826734-cbce-5aa0-5f98-605d303a0750",
          "assetData": {
            "GS1:functionalName": "Carbon dioxide",
            "GS1:country": "Spain"
          },
          "previousCredential": block_id,
          
        },
      }))?;
    
      //Build credential using subject above and issuer
      let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_doc.id().as_str())?)
    .type_("BCVerifiableSupplyChainCredential")
    .type_("AssetDataStandard")
    .subject(subject)
    .build()?;
    
    let credential_jwt: Jwt = issuer_doc
    .create_credential_jwt(
      &credential,
      &storage,
      &fragment,
      &JwsSignatureOptions::default(),
      None,
    )
    .await?;

    Ok(credential_jwt)
}

pub async fn create_vc_atto(
    storage: &Storage<StrongholdStorage, StrongholdStorage>,
    fragment: &str,
    issuer_doc: &IotaDocument,
    holder_doc: &IotaDocument,
    file_hash: &String
) -> anyhow::Result<Jwt> {
    let subject: Subject = Subject::from_json_value(json!({
        "holder": holder_doc.id().as_str(),
        "DocumentData": {
          "id": "a9826734-cbce-5aa0-5f98-605d303a0750",
          "assetData": {
            "functionalName": "atto_notarile",
            "country": "Italy"
          },
          "fileHash": file_hash,
          
        },
      }))?;
    
      //Build credential using subject above and issuer
      let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_doc.id().as_str())?)
    .type_("AssetDataStandard")
    .subject(subject)
    .build()?;
    
    let credential_jwt: Jwt = issuer_doc
    .create_credential_jwt(
      &credential,
      &storage,
      &fragment,
      &JwsSignatureOptions::default(),
      None,
    )
    .await?;

    Ok(credential_jwt)
}
///Generates a vp from the given credential as Jwt,
///  a Jwt representing the vp is returned upon success.
/// 
/// # Arguments
/// 
/// * 'jwt_cred': the Vc as Jwt to put in the Vp.
/// * 'challenge': a unique random challenge generated by the requester per presentation can mitigate reply attacks.
/// * 'holder_document': the IotaDocument holder document.
/// * 'storage': the storage that keeps the issuer information in order to sign jwt.
/// 
/// # Returns
/// 
/// * 'presentation': the Vp generated as Jwt
pub async fn create_vp(
    jwt_cred: Jwt,
    challenge: &str,
    holder_document: &IotaDocument,
    storage: &Storage<StrongholdStorage, StrongholdStorage>,
    fragment: &str, 
) -> anyhow::Result<Jwt> {

    //The verifier and the holder agree that the signature should have an expiry date.
    let expires: Timestamp = Timestamp::now_utc()
        .checked_add(identity_iota::core::Duration::minutes(10))
        .ok_or_else(|| anyhow::anyhow!("Failed to calculate expiration time"))?;


    //Create an unsigned Presentation from the previously issued Verifiable Credential
    let presentation: Presentation<Jwt> = PresentationBuilder::new(
        holder_document.id().to_url().into(),
        Default::default(),
    )
    .credential(jwt_cred)
    .build()?; 

    //Create a Jwt verifiable presentation using the holder's verification method 
    // and include the requested challenge and expiry timestamp
    let presentation_jwt: Jwt = holder_document
        .create_presentation_jwt(
            &presentation,
            &storage,
            &fragment,
            &JwsSignatureOptions::default().nonce(challenge.to_owned()),
            &JwtPresentationOptions::default().expiration_date(expires),
        )
        .await?; 

    Ok(presentation_jwt)
}

///Decodes and validates a Credential issued as a JWT. 
/// A DecodedJwtCredential is returned upon success.
/// 
/// # Arguments
/// 
/// * 'jwt_cred': the Vc as Jwt that has to be verified
/// * 'client': an IOTA node client.
/// 
/// # Returns
/// 
/// * 'decoded_credential': if the Vc is verified, returns the credential decoded
pub async fn verify_vc (
    jwt_cred: &Jwt,
    client: &Client
) -> anyhow::Result<DecodedJwtCredential> {

    //Extract the issuer did from the Vc jwt
    let issuer_did: IotaDID = JwtCredentialValidatorUtils::extract_issuer_from_jwt(&jwt_cred)?;

    let issuer_document: IotaDocument = client.resolve_did(&issuer_did).await?;

    //Validate the credential
    let decoded_credential: DecodedJwtCredential<Object> =
        JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
          .validate::<_, Object>(
            &jwt_cred,
            &issuer_document,
            &JwtCredentialValidationOptions::default(),
            FailFast::FirstError,
          )
          .unwrap();

    Ok(decoded_credential)
}

///Decodes and validates a Vp as a JWT.
///  A DecodedJwtPresentation is returned upon success.
/// 
/// # Arguments
/// 
/// * 'jwt_vp': the Vp as Jwt that has to be verified
/// * 'client': an IOTA node client.
/// * 'challenge': a unique random challenge generated by the requester per presentation can mitigate reply attacks.
/// 
/// # Returns
/// 
/// * 'decoded_presentation': if the Vp is verified, returns the presentation decoded
pub async fn verify_vp(
    jwt_vp: &Jwt,
    client: Client,
    challenge: &str
) -> anyhow::Result<DecodedJwtPresentation<Jwt>>{
    let presentation_verifier_options: JwsVerificationOptions =
        JwsVerificationOptions::default().nonce(challenge.to_owned());

    let mut resolver: Resolver<IotaDocument> = Resolver::new();
    resolver.attach_iota_handler(client);

    let holder_did: CoreDID = JwtPresentationValidatorUtils::extract_holder(&jwt_vp)?;
    let holder: IotaDocument = resolver.resolve(&holder_did).await?;

    let presentation_validation_options =
        JwtPresentationValidationOptions::default().presentation_verifier_options(presentation_verifier_options);
    let presentation: DecodedJwtPresentation<Jwt> = JwtPresentationValidator::with_signature_verifier(
        EdDSAJwsVerifier::default(),
    )
    .validate(&jwt_vp, &holder, &presentation_validation_options)?;

    Ok(presentation)
        
}

///recover the issuer storage that is needed for the emission of Vc
/// 
/// # Arguments
/// 
/// * 'stronghold_path': the local path where is stored the stronghold issuer file
/// * 'password': the password used by the issuer to keep the storage safe
/// 
/// # Returns
/// 
/// * 'Storage': The issuer Storage that keep the information to sign the Credential
pub async fn get_issuer_storage(
    stronghold_path: &str,
    password: &str
) -> anyhow::Result<Storage<StrongholdStorage, StrongholdStorage>> {
    let pass = Password::from(password.to_owned());
    let path = PathBuf::from(stronghold_path);

    let stronghold = StrongholdSecretManager::builder()
          .password(pass.clone())
          .build(path.clone())?;

    let stronghold_storage = StrongholdStorage::new(stronghold);
    let storage = Storage::new(stronghold_storage.clone(), stronghold_storage.clone());

    Ok(storage)
}

/// recover the previous vc from the Vc-chain
/// 
/// # Arguments
/// 
/// * 'jwt_vc': the Vc as Jwt containing the block_id of the previous Vc.
/// * 'issuer_doc': the issuer document of the issuer of the jwt_vc.
/// * 'client': an Iota node Client.
/// 
/// # Returns
/// 
/// * 'credential': the previous credential in the chain as Jwt
pub async fn recover_previous_vc(
    jwt_vc: &Jwt,
    issuer_doc: &IotaDocument,
    client: &Client
) -> anyhow::Result<Jwt> {
    let decoded_credential: DecodedJwtCredential<Object> =
    JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
      .validate::<_, Object>(
        &jwt_vc,
        &issuer_doc,
        &JwtCredentialValidationOptions::default(),
        FailFast::FirstError,
      )
      .unwrap();

    let cred = decoded_credential.credential;
    let cred_sub = cred.credential_subject;

    let cred_sub_json = cred_sub.to_json().unwrap();

    // Parsa la stringa JSON in un valore serde_json::Value
    let data: Value = serde_json::from_str(&cred_sub_json).unwrap();

    // Estrarre il campo "previousCredential" all'interno del campo "ChainData"
    let block_id2 = data["ChainData"]["previousCredential"].as_str().unwrap_or("Nessun block_id");

    let blockid:BlockId=BlockId::from_str(block_id2).unwrap();

    let old_cre = get_vc_from_block(&blockid, &client).await?;

    Ok(old_cre)
}

/// Recover the previous block from the interested Vc.
/// 
/// # Arguments
/// 
/// * 'jwt_vc': the Vc as Jwt containing the block_id of the previous Vc.
/// * 'issuer_doc': the issuer document of the issuer of the jwt_vc.
/// 
/// # Returns
/// 
/// * 'block_id': the previous block_id from the chain as string
pub async fn recover_previous_block(
    jwt_vc: &Jwt,
    issuer_doc: &IotaDocument
) -> anyhow::Result<String> {
    let decoded_credential: DecodedJwtCredential<Object> =
    JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
      .validate::<_, Object>(
        &jwt_vc,
        &issuer_doc,
        &JwtCredentialValidationOptions::default(),
        FailFast::FirstError,
      )
      .unwrap();

    let cred = decoded_credential.credential;
    let cred_sub = cred.credential_subject;

    let cred_sub_json = cred_sub.to_json().unwrap();

    // Parsa la stringa JSON in un valore serde_json::Value
    let data: Value = serde_json::from_str(&cred_sub_json).unwrap();

    // Estrarre il campo "nome" all'interno del campo "persona"
    let block_id2 = data["ChainData"]["previousCredential"].as_str().unwrap_or("null");

    Ok(block_id2.to_string())
}

///Push a block containing a Vc as jwt on the payload
/// 
/// # Arguments
/// 
/// * 'tag_str': the tag of the block that will be pushed into the Tangle
/// * 'data_jwt': the payload (usually a credential Jwt) of the block that will be pushed into the Tangle
/// * 'client': an IOTA node client.
/// 
/// # Returns
/// 
/// * 'block_id': the block_id of the pushed block
pub async fn push_block(
    tag_str: &str,
    data_jwt: &Jwt,
    client: &Client
) -> anyhow::Result<BlockId> {
    let jwt_string = data_jwt.as_str();

    //Create the block with the tag and data, then push it into the Tangle
    let tag = std::env::args().nth(1).unwrap_or_else(|| tag_str.to_string());
    let data = std::env::args().nth(2).unwrap_or_else(|| jwt_string.to_string());
    
    let block = client
    .build_block()
    .with_tag(tag.as_bytes().to_vec())
    .with_data(data.as_bytes().to_vec())
    .finish()
    .await?;

    Ok(block.id())

}

///recover a Vc as jwt from a block in the tangle
/// 
/// # Arguments
/// 
/// * 'block_id': the block identifier containig the interested Vc
/// * 'client': an IOTA node client
/// 
/// # Returns
/// 
/// * 'credential': the credential recovered from the block as Jwt
pub async fn get_vc_from_block(
    block_id: &BlockId,
    client: &Client
) -> anyhow::Result<Jwt> {
    //Get the block from the chain with the block_id
    let block = client.get_block(&block_id).await?;

    let mut jwt_string:String ="".to_string();

    //Extract the Payload(usually the credential jwt) from the block
    if let Some(Payload::TaggedData(payload)) = block.payload() {
        jwt_string = String::from_utf8(payload.data().to_vec()).expect("found invalid UTF-8");
        
    }
    let jwt = Jwt::from(jwt_string);

    Ok(jwt)
}

///Add with an append the block to the specified file
/// 
/// # Arguments
/// 
/// * 'tag': the name(tag) of the file that need to store the block_id.
/// * 'block_id': the block identifier that has to be store in the file.
/// 
/// # Returns
/// 
/// * 'string': a string that confirms writing the block_id to the file
pub async fn write_block(
    filename: &str,
    block_id: &BlockId
) -> anyhow::Result<String> {
    let block_str = block_id.to_string();

    let mut file = OpenOptions::new()
        .append(true)
        .open(filename.to_owned()+".txt")?;

    writeln!(file, "{}", block_str)?;

    Ok("ok".to_string())
}

///Gets the blocklist from the specified file 
/// 
/// # Arguments
/// 
/// * 'tag': the name(tag) of the file that store the searched blocklist
/// 
/// # Returns
/// 
/// * 'blocklist': a Vec of the block_id from the file
pub async fn get_blocklist(
    tag: &str
) -> anyhow::Result<Vec<BlockId>>{
    let file = File::open(tag.to_owned()+".txt")?;
    let reader = io::BufReader::new(file);

    //Creates a vec to contain read line
    let mut lines: Vec<String> = Vec::new();

    //Iter the line of the file and put them into the vec
    for line in reader.lines() {
        let line = line?;
        lines.push(line);
    }

    let mut blocklist: Vec<BlockId> = Vec::new();

    for line in &lines {
        let block_id:BlockId=BlockId::from_str(line).unwrap();
        blocklist.push(block_id);
    }

    Ok(blocklist)
}
