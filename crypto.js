const vectorSize = 16;
const utf8Encoder = new TextEncoder();
const utf8Dencoder = new TextDecoder();
const iterations = 1000;
const salt = utf8Encoder.encode('XHWnDAT6ehMVY2zD');


/** 获取加密按钮 */
let encryptBtn = document.getElementById('encryptBtn');
/** 获取解密按钮 */
let decryptBtn = document.getElementById('decryptBtn');
/** 获取复制原文按钮 */
let copyDecryptedBtn = document.getElementById('copyDecrypted');
/** 获取复制密文按钮 */
let copyEncryptedBtn = document.getElementById('copyEncrypted');
/** 获取复制清空按钮 */
let clearAllBtn = document.getElementById('clearAll');

/** 原文内容 */
let decryptedData = document.getElementById('decryptedData');
/** 密匙内容 */
let pass = document.getElementById('pass');
/** 加密内容 */
let encryptedData = document.getElementById('encryptedData');

/** 加密绑定点击事件 */
encryptBtn.addEventListener('click', handleEncryptClick)
/** 解密绑定点击事件 */
decryptBtn.addEventListener('click', handleDecryptClick);
/** 复制原文按钮绑定点击事件 */
copyDecryptedBtn.addEventListener('click', copyDecryptedFun);
/** 复制密文按钮绑定点击事件 */
copyEncryptedBtn.addEventListener('click', copyEncryptedFun);
/** 清空按钮绑定点击事件 */
clearAllBtn.addEventListener('click', clearAllFun);


/** 拷贝原文操作函数 */
async function copyDecryptedFun() {
    await navigator.clipboard.writeText(decryptedData.value);
}
/** 拷贝密文操作函数 */
async function copyEncryptedFun() {
    await navigator.clipboard.writeText(encryptedData.value);
}

/** 清空数据函数*/
async function clearAllFun() {
    decryptedData.value='';
    pass.value='';
    encryptedData.value='';
}

// 加密
async function handleEncryptClick() {
    const text = decryptedData.value;
    const password = pass.value;
    const base64Encoded = await encryptToBase64(text, password);
    encryptedData.value = base64Encoded;
}

// 解密
async function handleDecryptClick() {
    const base64Encoded = encryptedData.value;
    const password = pass.value;
    const text = await decryptFromBase64(base64Encoded, password);
    decryptedData.value = text;
}

/** -----------------------以下内容为加密算法------------------------------------- */

async function decryptFromBase64(base64Encoded, password) {
    const bytesToDecode = stringToArray(atob(base64Encoded));
    return await decryptFromBytes(bytesToDecode, password);
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






