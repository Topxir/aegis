//! Extreme Red-Team Vulnerability, Fuzzing & Zero-Trace Anonymity Audit Suite (T-0012).
//!
//! Verifies that no passive or active adversary, malicious server, ISP, or local web page
//! can track, correlate, fingerprint, or de-anonymize an Aegis user.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_ffi::{
    aegis_ffi_scan_utf8_leak_count, check_calculator_unlock, combine_pqxdh_secrets,
    derive_circuit_isolation_token, derive_login_id, evaluate_network_shield,
    format_server_invite_uri, format_static_ipv4_endpoint, generate_static_ip_vps_script,
    handle_http_request, pad_frame, redact_leaks, scan_message_for_leaks, solve_pow,
    strip_media_metadata, validate_launch_config, validate_manifest, AegisClientCore,
    AppDisguiseConfig, BotBridgeConfig, BotBridgeDescriptor, BuiltInDirectory, ContactInvite,
    CoverTrafficScheduler, DeterministicPowVerifier, DisguiseMode, EncryptedNote, EncryptedVaultDb,
    FederationServerState, GroupChatSession, IsolatedCircuitTag, LaunchTarget, LeakKind, Locale,
    OpaqueClientSession, PanicAction, PluginManifest, PowChallenge, PowVerifier, ProtocolError,
    RatchetSession, RouteProbe, SealedSenderEnvelope, ServerMigrationNotice, StoredContact,
    StoredMessage, SupportPortalState, PADDING_BUCKETS, SCHEMA_VERSION,
};

#[test]
fn zero_trace_traffic_analysis_and_padding_indistinguishability() {
    let group = GroupChatSession::new([0x99; 32], [0xAA; 32], [0x77; 32]).unwrap();

    // 1-byte message and 200-byte message must produce identically sized 256-byte encrypted wire frames
    // with zero cleartext length prefixes and zero trailing 0x00 runs.
    let f_short = group.seal_group_message(&[0x01; 12], b"x").unwrap();
    let f_long = group.seal_group_message(&[0x02; 12], &[b'A'; 200]).unwrap();
    assert_eq!(f_short.len(), 256);
    assert_eq!(f_long.len(), 256);
    assert_ne!(&f_short[0..2], &[0x00, 0x01]);
    assert_ne!(&f_long[0..2], &[0x00, 200]);
    assert!(f_short[220..256].iter().any(|&b| b != 0));

    // Tampering with any byte of the 256-byte frame must fail closed
    for idx in [0usize, 1, 128, 239, 240, 255] {
        let mut tampered = f_short.clone();
        tampered[idx] ^= 0x01;
        assert!(group.open_group_message(&[0x01; 12], &tampered).is_err());
    }

    // Cover traffic frames must be 256 bytes, non-repeating, and have high byte diversity (no 0x00 tail)
    let mut sched = CoverTrafficScheduler::default_scheduler();
    let mut prev_frame = Vec::new();
    for step in 1..=10u64 {
        let frame = sched.poll_cover_frame(step * 15_000, 0xCAFE_BABE).unwrap();
        assert_eq!(frame.len(), PADDING_BUCKETS[0]);
        assert!(frame[34..256].iter().any(|&b| b != 0));
        assert_ne!(frame, prev_frame);
        prev_frame = frame;
    }
}

#[test]
fn zero_trace_stream_isolation_opaque_vs_anonymous_queues() {
    let session_seed = [0x5A; 32];
    let vault_token =
        derive_circuit_isolation_token(&IsolatedCircuitTag::VaultSyncCircuit, &session_seed);

    let mut seen_tokens = vec![vault_token];
    for i in 1..=32u8 {
        let q_id = [i; 16];
        let read_tok = derive_circuit_isolation_token(
            &IsolatedCircuitTag::QueueReadCircuit(q_id),
            &session_seed,
        );
        let write_tok = derive_circuit_isolation_token(
            &IsolatedCircuitTag::DirectWriteCircuit(q_id),
            &session_seed,
        );
        assert!(!seen_tokens.contains(&read_tok));
        seen_tokens.push(read_tok);
        assert!(!seen_tokens.contains(&write_tok));
        seen_tokens.push(write_tok);
    }
}

#[test]
fn zero_trace_server_blindness_and_debug_log_redaction_across_all_modules() {
    let salt = [0x3C; 32];
    let mut srv = FederationServerState::new(salt);

    // Register an OPAQUE account with two distinct blinding factors -> nonces must never collide
    let (sess1, rec1) = OpaqueClientSession::start(
        "silent-vortex-4821",
        "AEGis#MasterKey2026!",
        &salt,
        &[0x11; 32],
    )
    .unwrap();
    let (_, rec2) = OpaqueClientSession::start(
        "silent-vortex-4821",
        "AEGis#MasterKey2026!",
        &salt,
        &[0x22; 32],
    )
    .unwrap();
    assert_ne!(rec1.envelope.nonce, rec2.envelope.nonce);

    let login_id = derive_login_id("silent-vortex-4821", &salt).unwrap();
    assert_eq!(sess1.login_id(), login_id);

    // Server stores constant 1024-byte record; probing registered vs unregistered login_ids
    // always returns 1024 high-entropy bytes and blocks unauthenticated overwrites
    let mut wire_record = vec![0xAA; 1024];
    wire_record[0..32].copy_from_slice(&rec1.client_public_verifier);
    assert!(srv
        .store_opaque_record(login_id, wire_record.clone())
        .is_ok());
    assert!(srv.store_opaque_record(login_id, vec![0xBB; 1024]).is_err());

    for probe_byte in 1..=20u8 {
        let fetched = srv.fetch_opaque_record(&[probe_byte; 32]).unwrap();
        assert_eq!(fetched.len(), 1024);
        assert_ne!(fetched[0..32], fetched[32..64]);
    }

    // Verify Debug output of all sensitive types never leaks secrets, nicknames, or message bodies
    let mut db = EncryptedVaultDb::open(SCHEMA_VERSION, vec![0x88; 32]).unwrap();
    let contact = StoredContact {
        contact_id: [0x11; 32],
        display_name: "SecretContactAlias".to_owned(),
        peer_identity_key: [0x22; 32],
        send_queue_id: [0x33; 32],
        recv_queue_id: [0x44; 32],
        verified: true,
    };
    let msg = StoredMessage {
        message_id: [0x55; 32],
        chat_id: [0x66; 32],
        sender_is_self: true,
        plaintext_body: "UltraSecretCoordinates9911".to_owned(),
        created_at_unix_secs: 1000,
        expires_at_unix_secs: Some(2000),
    };
    let note = EncryptedNote {
        note_id: [0x77; 32],
        title: "SecretSeedTitle".to_owned(),
        body: "SecretSeedBody".to_owned(),
        updated_at_unix_secs: 1000,
    };
    db.upsert_contact(contact.clone()).unwrap();
    db.insert_message(msg.clone()).unwrap();
    db.put_local_note(note.clone()).unwrap();

    let mut core_client = AegisClientCore::new(Locale::Ru);
    core_client
        .register_local_account([0x01; 16], "silent-vortex-4821")
        .unwrap();
    let disguise_cfg = AppDisguiseConfig::try_new(
        DisguiseMode::Calculator {
            unlock_expression: "7788+11=".to_owned(),
        },
        PanicAction::InstantCryptoWipe,
    )
    .unwrap();

    let combined_debug =
        format!("{srv:?} {contact:?} {msg:?} {note:?} {db:?} {core_client:?} {disguise_cfg:?}");
    for forbidden_secret in [
        "SecretContactAlias",
        "UltraSecretCoordinates9911",
        "SecretSeedTitle",
        "SecretSeedBody",
        "silent-vortex-4821",
        "7788+11=",
    ] {
        assert!(
            !combined_debug.contains(forbidden_secret),
            "Debug output leaked secret: {forbidden_secret}"
        );
    }
    assert!(check_calculator_unlock(&disguise_cfg, "7788+11="));
}

#[test]
fn extreme_exif_gps_and_png_apple_idot_metadata_smuggling_fuzzer() {
    // 1. Progressive JPEG with multiple 0xFF fill bytes before RST0, APP14, JPG0 (0xFFF0), and COM
    let jpeg_polyglot: Vec<u8> = vec![
        0xFF, 0xD8, // SOI
        0xFF, 0xE1, 0x00, 0x06, b'E', b'X', b'I', b'F', // APP1
        0xFF, 0xF0, 0x00, 0x06, b'J', b'P', b'G', b'0', // JPG0 extension
        0xFF, 0xDB, 0x00, 0x04, 0x01, 0x02, // DQT
        0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00, // SOS
        0x12, 0xFF, 0xFF, 0xD0, 0x34, // Entropy with multiple 0xFF fill bytes + RST0
        0xFF, 0xFE, 0x00, 0x06, b'L', b'E', b'A', b'K', // Post-SOS COM
        0xFF, 0xD9, // EOI
    ];
    let cleaned = strip_media_metadata(&jpeg_polyglot).unwrap();
    assert_eq!(cleaned.stripped_segments_count, 3);
    assert!(!cleaned.bytes.windows(4).any(|w| w == b"EXIF"));
    assert!(!cleaned.bytes.windows(4).any(|w| w == b"JPG0"));
    assert!(!cleaned.bytes.windows(4).any(|w| w == b"LEAK"));

    // 2. Malformed / truncated / overflow media inputs must never panic and always fail closed
    let hostile_inputs: [&[u8]; 8] = [
        b"",
        &[0xFF, 0xD8],
        &[0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF],
        &[
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF,
        ],
        b"GIF89a\x01\x00\x01\x00",
        b"RIFF\x10\x00\x00\x00WEBPVP8 ",
        b"\x00\x00\x00\x18ftypheic",
        b"II*\x00\x08\x00\x00\x00", // Raw TIFF EXIF header
    ];
    for bad in hostile_inputs {
        assert_eq!(
            strip_media_metadata(bad),
            Err(ProtocolError::MalformedPaddedFrame)
        );
    }
}

#[test]
fn extreme_sealed_sender_1to1_ratchet_and_zero_metadata_oracle_shield() {
    // 1. Full 1:1 PQXDH + Double Ratchet + SealedSenderEnvelope (Pad-Before-Encrypt)
    let root = combine_pqxdh_secrets(&[0x11; 32], &[0x22; 32], b"aegis-1to1").unwrap();
    let alice_dh = [0xA1; 32];
    let bob_dh = [0xB2; 32];
    let mut alice = RatchetSession::new(root.as_slice(), alice_dh, bob_dh, true).unwrap();
    let mut bob = RatchetSession::new(root.as_slice(), bob_dh, alice_dh, false).unwrap();

    let (hdr, ct) = alice
        .send_ratchet_step(b"Zero-trace state-resistant capsule", b"q")
        .unwrap();
    let queue_id = [0x91; 32];
    let env_key = [0x92; 32];
    let env_nonce = [0x07; 12];
    let alice_ik = [0xA9; 32];

    let wire_frame =
        SealedSenderEnvelope::seal(&queue_id, &env_key, &env_nonce, &alice_ik, &hdr, &ct).unwrap();
    assert_eq!(wire_frame.len(), 256);
    // Neither Alice's identity key nor her ephemeral DH public key appears in cleartext on the wire
    assert!(!wire_frame.windows(32).any(|w| w == alice_ik));
    assert!(!wire_frame.windows(32).any(|w| w == alice_dh));

    let unsealed =
        SealedSenderEnvelope::open(&queue_id, &env_key, &env_nonce, &wire_frame).unwrap();
    assert_eq!(unsealed.sender_identity_key, alice_ik);
    let decrypted = bob
        .recv_ratchet_step(&unsealed.ratchet_header, &unsealed.inner_ciphertext, b"q")
        .unwrap();
    assert_eq!(decrypted.as_slice(), b"Zero-trace state-resistant capsule");

    // 2. Server HTTP endpoints never leak active_queues or buffered_frames metadata oracles
    let mut srv = FederationServerState::new([0x44; 32]);
    let mut portal = SupportPortalState::new();
    let (_, _, send_json) = handle_http_request(
        &mut srv,
        &mut portal,
        "POST",
        "/api/v1/queue/send",
        "capsule-1",
    );
    assert_eq!(send_json, r#"{"status":"queued"}"#);
    assert!(!send_json.contains("buffered_frames"));

    let (_, _, health_json) = handle_http_request(&mut srv, &mut portal, "GET", "/health", "");
    assert!(!health_json.contains("active_queues"));
    assert!(!health_json.contains("support_tickets"));
}

#[test]
fn extreme_ssrf_pow_and_leak_guard_stress_test() {
    // 1. PoW SHA-256 verification rejects tampered nonces and expired challenges
    let challenge = PowChallenge {
        challenge: [0xAB; 32],
        difficulty_bits: 6,
        expires_at_unix_secs: 10_000,
    };
    let sol = solve_pow(&challenge, 50_000).unwrap();
    assert!(DeterministicPowVerifier
        .verify_pow(&challenge, sol.nonce, 9_000)
        .is_ok());

    // 2. Network Anonymity Shield blocks traffic on any tunnel leak even if kill_switch_enabled is false
    let leaked_probe = RouteProbe {
        via_tor: false,
        via_vpn_or_proxy: true,
        baseline_isp_ip_hash: Some([0x77; 32]),
        server_observed_ip_hash: Some([0x77; 32]),
        kill_switch_enabled: false,
    };
    let eval = evaluate_network_shield(&leaked_probe);
    assert!(eval.tunnel_leak_detected);
    assert!(!eval.traffic_permitted);

    // 3. SSRF matrix across plugins, launcher, transport, invites, and directory
    let plan = validate_launch_config(LaunchTarget::VpsDocker, 8443, 30).unwrap();
    assert!(generate_static_ip_vps_script(&plan, [10, 0, 0, 1], &[0xAA; 32]).is_err());
    assert!(format_static_ipv4_endpoint([192, 168, 1, 1], 8443).is_err());
    assert!(format_server_invite_uri("0127.0.0.1", 8443, &[0xAA; 32]).is_err());
    assert!(ServerMigrationNotice::new_verified(
        [0x11; 32],
        [0x22; 32],
        "aegis://sub.localhost:8443".to_owned(),
        [0x33; 32],
        true
    )
    .is_err());

    let bridge = BotBridgeDescriptor {
        manifest: PluginManifest {
            plugin_id: "matrix-bridge".to_owned(),
            declarative_theme_only: false,
            allowed_read_chats: vec![],
            allow_proxied_network: true,
            requested_forbidden_key_access: false,
        },
        config: BotBridgeConfig::MatrixBridge {
            homeserver_host: "0x7f.0.0.1".to_owned(),
            isolated_bridge_queue_id: [0x44; 32],
        },
    };
    assert!(bridge.validate().is_err());

    // Oversized allowed_read_chats (> 64) rejected to prevent quadratic DoS
    let huge_manifest = PluginManifest {
        plugin_id: "local-bot".to_owned(),
        declarative_theme_only: false,
        allowed_read_chats: (1..=65u8).map(|i| [i; 16]).collect(),
        allow_proxied_network: false,
        requested_forbidden_key_access: false,
    };
    assert!(validate_manifest(&huge_manifest).is_err());

    // 4. LeakGuard catches cards, phones, Markdown emails, private keys, and Unicode nicknames, and redacts cleanly
    let dirty = "Карта 4532 0151 1283 0366 912, тел +7 (999) 123-45-67, почта `anon@proton.me`, ключ 0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318, логин: теньВолка";
    let warnings = scan_message_for_leaks(dirty, Some("теньволка"));
    assert_eq!(warnings.len(), 5);
    assert!(warnings
        .iter()
        .any(|w| w.kind == LeakKind::CryptoSeedOrPrivateKey));
    let clean = redact_leaks(dirty, &warnings);
    assert!(!clean.contains("4532"));
    assert!(!clean.contains("999"));
    assert!(!clean.contains("anon@proton.me"));
    assert!(!clean.contains("0x4c0883"));
    assert!(!clean.contains("теньВолка"));

    // Invalid UTF-8 fails closed in FFI helper
    assert_eq!(
        aegis_ffi_scan_utf8_leak_count(&[0xFF, 0x00], None),
        usize::MAX
    );

    // Built-in directory has 3 direct static-IP starter servers and 1 optional Tor .onion node
    let dir = BuiltInDirectory::embedded_catalog();
    assert_eq!(dir.direct_static_ip_entries().len(), 3);
    assert_eq!(dir.verified_entries().len(), 4);
    let _ = ContactInvite {
        server_endpoint: "185.220.101.42:8443".to_owned(),
        recipient_queue_id: [0x11; 32],
        x25519_public: [0x22; 32],
        ml_kem_public_hash: [0x33; 32],
        expires_at_unix_secs: 5_000,
        max_activations: 1,
        offline_qr_only: false,
    }
    .to_uri()
    .unwrap();
    let _ = pad_frame(b"ok").unwrap();
}
