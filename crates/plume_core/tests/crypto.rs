use aes::Aes256;
use aes::cipher::consts::U16;
use aes_gcm::aead::Aead;
use aes_gcm::{AesGcm, KeyInit, Nonce};

#[test]
fn test_compatibility() {
    let sk: [u8; 32] = [
        45, 250, 82, 166, 236, 5, 49, 115, 40, 116, 140, 106, 192, 125, 35, 63, 62, 89, 122, 76, 206,
        249, 239, 218, 126, 5, 248, 7, 91, 248, 242, 207,
    ];
    let iv: [u8; 16] = [0; 16];
    let header = b"XYZ";

    // 验证 sk 的长度
    assert_eq!(sk.len(), 32);

    // 1. 测试密钥和 Cipher 初始化
    let key_res = aes_gcm::Key::<AesGcm<Aes256, U16>>::try_from(sk.as_slice());
    assert!(key_res.is_ok(), "Key creation from sk failed");

    let key = key_res.unwrap();
    let cipher = AesGcm::<Aes256, U16>::new(&key);

    // 2. 测试 16 字节 Nonce 初始化 (代码中使用 Nonce::<U16>)
    let nonce_res = Nonce::<U16>::try_from(iv.as_slice());
    assert!(nonce_res.is_ok(), "Nonce creation from iv failed");
    let nonce = nonce_res.unwrap();

    // 3. 测试加密和解密流程，确保没有 Panic
    let plaintext = b"Hello Apple";
    let ciphertext = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: header,
            },
        )
        .expect("Encryption should succeed");

    let decrypted = cipher
        .decrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: &ciphertext,
                aad: header,
            },
        )
        .expect("Decryption should succeed");

    assert_eq!(decrypted, plaintext);
}
