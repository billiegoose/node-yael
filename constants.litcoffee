# Settings

    module.exports =
        CIPHER_ALGORITHM : 'aes-256-gcm'

After doing some research, I decided the encryption cipher that was the best choice for this project at the time
of writing was AES-256-GCM.
* Why AES? Well, it apparently is still state-of-the-art. Maybe the NSA can break it, but it
seems to be the goto standard for symmetric encryption.
* Why 256? Because that's the largest key size that Node's
crypto library lists on my computer. As larger key sizes become the norm, I'm sure the key size will increase.
* Why GCM? Earlier AES block cipher modes provide confidentiality, but do not ensure file integrity.
Those AES modes must be combined with another algorithm to ensure that the file hasn't been tampered with or
accidentally corrupted. AES-GCM is the only AES algorithm at the time of writing that combines file decryption
and verification.

        SALT_LENGTH : 16
        IV_LENGTH : 12
        KEY_LENGTH : 32

These are the cipher settings. Note: AES-256-GCM is very picky about these numbers. Took me a while to get them right.
It just... doesn't work with different numbers. OpenSSL's fault I think. It took some Googling.

        AUTHTAG_LENGTH : 16

I don't think I even have control over this one. I just measured how long the auth tag that crypto gives back.

        HASH_ALGORITHM : 'sha256'
        ITERATIONS : 1000

These are settings for the key derivation function. These are independent of the cipher, and could be different.
SHA-256 seems standard. 1000 iterations seemed reasonable, but now that I'm reading up on it, a rule of thumb is
you want enough iterations so that for a given password+salt combination, it takes at least 8ms to compute the key.
Since this library is intended for one-off encryptions, not encrypting hundreds of messages per second, it might be
wise to increase the number greatly. I could even build in a year factor to account for Moore's Law.
