use e3_compute_provider::Batching;
use e3_openvm_types::{ComputeDomain, ComputeJournal, GuestHeader, write_items};
use interfold_auction_bfv_slots::{
    Anchor, Manifest, bytes, compute, encrypt_bid, encrypt_bid_for_proof, fhe_processor, fixed,
    hex, keccak, policy, program_input, reveal,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, Read, Write},
    path::Path,
    process,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivateBid {
    slot: usize,
    bid: u64,
    max_tick: u64,
}
fn read_json<T: DeserializeOwned>(path: &str) -> Result<T, String> {
    let mut raw = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(30_000_001)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 30_000_000 {
        return Err("JSON artifact too large".into());
    }
    serde_json::from_slice(&raw).map_err(|e| e.to_string())
}
fn fingerprint(raw: &[u8]) -> serde_json::Value {
    json!({"bytes":raw.len(),"keccak256":hex(&keccak(raw)),"sha256":hex(&Sha256::digest(raw))})
}
fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().skip(1).collect();
    let result=match args.first().map(String::as_str) {
        Some("encrypt" | "encrypt-for-proof") if (args[0]=="encrypt" && args.len()==3) || (args[0]=="encrypt-for-proof" && args.len()==4) => {
            // Private bid stays off argv and is never copied into the output or parse errors.
            let mut private=String::new(); io::stdin().take(4097).read_to_string(&mut private).map_err(|e|e.to_string())?;
            if private.len()>4096 { return Err("private input too large".into()); }
            let input:PrivateBid=serde_json::from_str(&private).map_err(|_|"invalid private bid JSON")?;
            let key_text=fs::read_to_string(&args[1]).map_err(|e|e.to_string())?;
            let key=bytes(key_text.trim())?; let expected=fixed(&args[2])?;
            if args[0]=="encrypt-for-proof" {
                let (public,private)=encrypt_bid_for_proof(&key,expected,input.slot,input.bid,input.max_tick)?;
                #[cfg(unix)] {
                    use std::os::unix::fs::{DirBuilderExt,OpenOptionsExt,PermissionsExt};
                    let dir=Path::new(&args[3]);
                    fs::DirBuilder::new().mode(0o700).create(dir).map_err(|_|"private witness destination must be a NEW directory")?;
                    fs::set_permissions(dir,fs::Permissions::from_mode(0o700)).map_err(|_|"private witness directory permission failed")?;
                    let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(dir.join("bid.private.json")).map_err(|_|"private witness file creation failed")?;
                    file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|_|"private witness file permission failed")?;
                    serde_json::to_writer(&mut file,&private).map_err(|_|"private witness write failed")?;
                    file.write_all(b"\n").map_err(|_|"private witness write failed")?;
                    file.sync_all().map_err(|_|"private witness sync failed")?;
                    fs::File::open(dir).and_then(|f|f.sync_all()).map_err(|_|"private witness directory sync failed")?;
                }
                #[cfg(not(unix))] { return Err("encrypt-for-proof requires Unix private-file permissions".into()); }
                serde_json::to_value(public).map_err(|e|e.to_string())?
            } else {
                serde_json::to_value(encrypt_bid(&key,expected,input.slot,input.bid,input.max_tick)?).map_err(|e|e.to_string())?
            }
        },
        Some("compute-native") if args.len()==3 => {
            let manifest:Manifest=read_json(&args[1])?; let anchor:Anchor=read_json(&args[2])?;
            serde_json::to_value(compute(&manifest,&anchor)?).map_err(|e|e.to_string())?
        },
        Some("prepare-openvm") if args.len()==5 => {
            let manifest:Manifest=read_json(&args[1])?; let anchor:Anchor=read_json(&args[2])?;
            let protocol=fixed::<20>(&args[3])?; if protocol==[0;20] { return Err("zero verifying protocol address".into()); }
            let input=program_input(&manifest,&anchor)?;
            let (result,aggregate,selected)=input.run_selected(fhe_processor,policy(),Batching::Sequential).map_err(|e|e.to_string())?;
            let e3_word=interfold_auction_bfv_slots::uint256_word(&anchor.e3_id)?;
            let domain=ComputeDomain { chain_id:11155111,verifying_contract:protocol,e3_id:e3_word,encryption_scheme_id:keccak(b"fhe.rs:BFV"),committee_public_key_hash:fixed(&anchor.committee_public_key)? };
            let journal=ComputeJournal::new(&domain,&result)?.abi_bytes();
            let header=GuestHeader { domain,params:input.fhe_inputs.params.clone(),indices:input.fhe_inputs.ciphertexts.iter().map(|(_,i)|*i).collect(),published:input.published.clone() }.encode()?;
            let mut items=vec![header];
            items.extend(input.fhe_inputs.ciphertexts.iter().map(|(ct,_)|ct.clone()));
            items.extend(selected.iter().map(|i|input.fhe_inputs.ciphertexts[*i].0.clone()));
            let mut framed=Vec::new(); write_items(&mut framed,items.iter().map(Vec::as_slice)).map_err(|e|e.to_string())?;
            let dir=Path::new(&args[4]); fs::create_dir(dir).map_err(|e|format!("output directory must be new: {e}"))?;
            fs::write(dir.join("input.bin"),&framed).map_err(|e|e.to_string())?;
            fs::write(dir.join("journal.bin"),&journal).map_err(|e|e.to_string())?;
            fs::write(dir.join("aggregate.bin"),&aggregate).map_err(|e|e.to_string())?;
            let metadata=json!({"scope":"public-openvm-input-bundle-not-a-proof","input":fingerprint(&framed),"journal":fingerprint(&journal),"aggregate":fingerprint(&aggregate),"guestItems":items.len(),"poseidonInputRoot":hex(&result.merkle_root),"paramsHash":hex(&result.params_hash),"openvmReceiptGenerated":false,"inputProofsVerified":false,"availabilityVerified":false});
            fs::write(dir.join("bundle.json"),format!("{}\n",serde_json::to_string_pretty(&metadata).map_err(|e|e.to_string())?)).map_err(|e|e.to_string())?;
            metadata
        },
        Some("reveal") if args.len()==4 => {
            let text=fs::read_to_string(&args[1]).map_err(|e|e.to_string())?;
            let count=args[2].parse().map_err(|_|"invalid bid count")?; let max_tick=args[3].parse().map_err(|_|"invalid max tick")?;
            json!({"ticks":reveal(&bytes(text.trim())?,count,max_tick)?,"source":"untrusted-bytes-must-be-read-from-finalized-e3-plaintextOutput"})
        },
        Some("transcript") if args.len()==2 => {
            let manifest:Manifest=read_json(&args[1])?; let context=fixed::<32>(&manifest.anchor.context)?;
            let mut root=context; let mut inputs=Vec::new();
            for input in &manifest.inputs {
                root=interfold_auction_bfv_slots::next_root(&root,input)?;
                inputs.push(json!({"slot":input.slot,"bidder":input.bidder,"envelope":input.envelope,"commitment":input.commitment,"poseidonLeaf":interfold_auction_bfv_slots::leaf_field(&context,input)?,"rollingRootAfter":hex(&root)}));
            }
            json!({"context":hex(&context),"inputs":inputs,"rollingRoot":hex(&root),"scope":"public-transcript-format-vector-no-proof-verification"})
        },
        Some("hash-artifact") if args.len()==2 => fingerprint(&fs::read(&args[1]).map_err(|e|e.to_string())?),
        _ => return Err("usage: auction-compute encrypt PUBLIC_KEY_HEX_FILE EXPECTED_SAFE_KEY_COMMITMENT < PRIVATE_BID_JSON | encrypt-for-proof PUBLIC_KEY_HEX_FILE EXPECTED_SAFE_KEY_COMMITMENT NEW_PRIVATE_DIRECTORY < PRIVATE_BID_JSON | compute-native MANIFEST_JSON INDEPENDENT_CHAIN_ANCHOR_JSON | prepare-openvm MANIFEST_JSON INDEPENDENT_CHAIN_ANCHOR_JSON PROTOCOL_ADDRESS NEW_OUTPUT_DIRECTORY | reveal PUBLIC_OUTPUT_HEX_FILE BID_COUNT MAX_TICK | transcript MANIFEST_JSON | hash-artifact FILE".into())
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("auction-compute: {error}");
        process::exit(1);
    }
}
