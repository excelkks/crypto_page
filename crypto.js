const vectorSize = 16;
const utf8Encoder = new TextEncoder();
const utf8Dencoder = new TextDecoder();
const iterations = 1000;
const salt = utf8Encoder.encode('XHWnDAT6ehMVY2zD');

async function deriveKey(password) {
    const buffer = utf8Encoder.encode(password)
    const key = await crypto.subtle.importKey(
        'raw',
        buffer,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    const privateKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            hash: { name: 'SHA-256' },
            iterations,
            salt
        },
        key,
        {
            name: 'AES-GCM',
            length: 256
        },
        false,
        ['encrypt', 'decrypt']
    );
    return privateKey;
}


async function encryptToBytes(text, password) {
    const key = await deriveKey(password);
    const textBytesToEncrypt = utf8Encoder.encode(text);
    const vector = crypto.getRandomValues(new Uint8Array(vectorSize));
    const encryptedBytes = new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: 'AES-GCM', iv: vector
            },
            key,
            textBytesToEncrypt
        )
    );

    const finalBytes = new Uint8Array( vector.byteLength + encryptedBytes.byteLength);
    finalBytes.set(vector, 0);
    finalBytes.set( encryptedBytes, vector.byteLength );

    return finalBytes;
}

function converToString( bytes ) {
    let result = '';
    for ( let idx = 0; idx < bytes.length; idx++) {
        result += String.fromCharCode(bytes[idx]);
    }
    return result;
}

async function encryptToBase64(text, password) {
    const finalBytes = await encryptToBytes(text, password);

    const base64Text = btoa(converToString(finalBytes));

    return base64Text;
}

function stringToArray(str) {
    const result = [];
    for(let i = 0; i < str.length; i++) {
        result.push(str.charCodeAt(i));
    }
    return new Uint8Array(result);
}

async function decryptFromBytes(encryptedBytes, password) {
    const vector = encryptedBytes.slice(0, vectorSize);
    const encryptedTextBytes = encryptedBytes.slice(vectorSize);
    const key = await deriveKey(password);
    const decryptedBytes = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: vector},
        key,
        encryptedTextBytes
    );

    const decryptedText = utf8Dencoder.decode(decryptedBytes);
    return decryptedText;
}

async function decryptFromBase64(base64Encoded, password) {
    const bytesToDecode = stringToArray(atob(base64Encoded));
    return await decryptFromBytes(bytesToDecode, password);
}

async function handleDecryptClick() {
    let decryptedData =  document.getElementById('decryptedData');
    let encryptedData =  document.getElementById('encryptedData');
    let pass =  document.getElementById('pass');
    const base64Encoded = encryptedData.value;
    const password = pass.value;
    const text = await decryptFromBase64(base64Encoded, password);
    decryptedData.value = text;
}

async function handleEncryptClick() {
    let decryptedData =  document.getElementById('decryptedData');
    let encryptedData =  document.getElementById('encryptedData');
    let pass =  document.getElementById('pass');
    const text = decryptedData.value;
    const password = pass.value;
    const base64Encoded = await encryptToBase64(text, password);
    encryptedData.value = base64Encoded;
}