const msgInput = document.querySelector('#msg-input');
const msgPass = document.querySelector('#msg-pass');
const encryptBtn = document.querySelector('#encrypt-btn');
const decryptBtn = document.querySelector('#decrypt-btn');
const msgOutput = document.querySelector('#msg-output');
const copyOutput = document.querySelector('#copy-output');

encryptBtn.addEventListener('click', e => {
  e.preventDefault();
  if (msgPass.value === '') {
    return;
  }
  encryptMessage();
});

decryptBtn.addEventListener('click', e => {
  e.preventDefault();
  if (msgPass.value === '') {
    return;
  }
  decryptMessage();
});

copyOutput.addEventListener('click', () => {
  const dummyTA = document.createElement('textarea');
  dummyTA.style.position = 'absolute';
  dummyTA.style.left = '-9999px';
  dummyTA.setAttribute('tabindex', '-1');
  document.body.appendChild(dummyTA);
  dummyTA.value = msgOutput.textContent;
  dummyTA.focus();
  dummyTA.select();
  document.execCommand('copy');
  document.body.removeChild(dummyTA);
  msgInput.focus();
});

msgInput.select();

function encryptMessage() {
  const saltIV = generateSaltIV();
  const textEncoder = new window.TextEncoderLite('utf-8');
  window.crypto.subtle.importKey(
    'raw',
    textEncoder.encode(msgPass.value),
    {name: 'PBKDF2'},
    false,
    ['deriveKey']
  ).then(passMaterial => window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltIV,
      iterations: 100000,
      hash: 'SHA-256'
    },
    passMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    [ 'encrypt' ]
  )).then(key => window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: saltIV
      },
      key,
      textEncoder.encode(msgInput.value)
  )).then(cipherBuffer => {
    const ciphertext = window.base64js.fromByteArray(new Uint8Array(cipherBuffer));
    msgOutput.value = window.base64js.fromByteArray(saltIV) + ciphertext;
    msgPass.value = '';
    msgInput.value = '';
  });
}

function decryptMessage() {
  const textEncoder = new window.TextEncoderLite('utf-8');
  const textDecoder = new window.TextDecoderLite('utf-8');
  const saltIV = new Uint8Array(window.base64js.toByteArray(msgInput.value.slice(0,24)));
  const ciphertext = new Uint8Array(window.base64js.toByteArray(msgInput.value.slice(24)));
  window.crypto.subtle.importKey(
    'raw',
    textEncoder.encode(msgPass.value),
    {name: 'PBKDF2'},
    false,
    ['deriveKey']
  ).then(passMaterial => window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltIV,
      iterations: 100000,
      hash: 'SHA-256'
    },
    passMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    [ 'decrypt' ]
  )).then(key => window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: saltIV
    },
    key,
    ciphertext
  )).then(plaintext => {
    msgOutput.value = textDecoder.decode(new Uint8Array(plaintext));
    msgPass.value = '';
    msgInput.value = '';
  });
}

/*
 * Using the same value as both the salt and the IV is only allowable if a new
 * value is generated for every message as we are doing here.
 */
function generateSaltIV() {
  return window.crypto.getRandomValues(new Uint8Array(16));
}
