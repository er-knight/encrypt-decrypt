document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("encryption-form-wrapper").style.display = "none";
    document.getElementById("decryption-form-wrapper").style.display = "none";
    document.getElementById("output-container-wrapper").style.display = "none";
})

document.getElementById("show-encryption-form").addEventListener("click", function () {
    document.getElementById("encryption-form-wrapper").style.display = "flex";
    document.getElementById("decryption-form-wrapper").style.display = "none";
    document.getElementById("output-container-wrapper").style.display = "none";

    document.getElementById("encryption-form").addEventListener("submit", function (event) {
        event.preventDefault();

        const plaintext = document.getElementById("plaintext").value;
        const password = document.getElementById("encryption-password").value;

        const encoder = new TextEncoder();
        const plaintextBytes = encoder.encode(plaintext);
        const passwordBytes = encoder.encode(password);

        encryptWith_AES_GCM(plaintextBytes, passwordBytes)
            .then(function (IVSaltCiphertextBytes) {
                document.getElementById("output-container-wrapper").style.display = "flex";
                document.getElementById("output-container-label").textContent = "Encryted Text";

                const base64IVSaltCiphertextBytes = btoa(String.fromCharCode(...IVSaltCiphertextBytes));
                document.getElementById("output-container").textContent = base64IVSaltCiphertextBytes;
            })
            .catch((error) => console.log(error))
    });
});

document.getElementById("show-decryption-form").addEventListener("click", function () {
    document.getElementById("encryption-form-wrapper").style.display = "none";
    document.getElementById("decryption-form-wrapper").style.display = "flex";
    document.getElementById("output-container-wrapper").style.display = "none";

    document.getElementById("decryption-form").addEventListener("submit", function (event) {
        event.preventDefault();

        const base64IVSaltCiphertextBytes = document.getElementById("ciphertext").value;
        const password = document.getElementById("decryption-password").value;
        const contentType = document.getElementById("content-type").value;

        const ciphertextBytes = base64ToUint8Array(base64IVSaltCiphertextBytes);

        const encoder = new TextEncoder();
        const passwordBytes = encoder.encode(password);

        decryptWith_AES_GCM(ciphertextBytes, passwordBytes)
            .then(function (plaintextBytes) {
                document.getElementById("output-container-wrapper").style.display = "flex";
                document.getElementById("output-container-label").textContent = "Decryted Text";

                const decoder = new TextDecoder();
                const plaintext = decoder.decode(plaintextBytes);
                if (contentType === "json") {
                    document.getElementById("output-container").textContent = JSON.stringify(JSON.parse(plaintext), null, 4);
                } else {
                    document.getElementById("output-container").textContent = plaintext;
                }
            })
            .catch((error) => console.log(error))
    });
});

async function encryptWith_AES_GCM(plaintextBytes, passwordBytes) {
    // Derive a key from the password using a suitable KDF
    const passwordKey = await crypto.subtle.importKey('raw', passwordBytes, { name: 'PBKDF2' }, false, ['deriveKey']);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 480000, hash: 'SHA-256' },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );

    // Encrypt the data using AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertextBytes = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintextBytes);

    console.log("IVSaltCiphertextBytes", iv, salt, new Uint8Array(ciphertextBytes));

    // Concatenate the IV and salt with the ciphertext into single Uint8Array
    const IVSaltCiphertextBytes = new Uint8Array(iv.length + salt.length + ciphertextBytes.byteLength);
    IVSaltCiphertextBytes.set(iv, 0);
    IVSaltCiphertextBytes.set(salt, iv.length);
    IVSaltCiphertextBytes.set(new Uint8Array(ciphertextBytes), iv.length + salt.length);

    return IVSaltCiphertextBytes;
}

async function decryptWith_AES_GCM(IVSaltCiphertextBytes, passwordBytes) {
    // Split the concatenated data into IV, salt, and ciphertext
    const iv = IVSaltCiphertextBytes.slice(0, 12);
    const salt = IVSaltCiphertextBytes.slice(12, 28);
    const ciphertextBytes = IVSaltCiphertextBytes.slice(28);

    console.log("IVSaltCiphertextBytes", iv, salt, ciphertextBytes);

    // Derive a key from the password using the retrieved salt
    const passwordKey = await crypto.subtle.importKey('raw', passwordBytes, { name: 'PBKDF2' }, false, ['deriveKey']);
    const aesKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 480000, hash: 'SHA-256' },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );

    // Decrypt the ciphertext using AES-GCM
    const plaintextBytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertextBytes);

    return new Uint8Array(plaintextBytes);
}

function base64ToUint8Array(base64String) {
    const binaryString = atob(base64String);
    const uint8Array = new Uint8Array(binaryString.length);

    for (let i = 0; i < binaryString.length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
    }

    return uint8Array;
}