let masterPassword = null;

// Function to generate a random password
function generatePassword(length = 12) {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~";
  let password = "";
  for (let i = 0, n = charset.length; i < length; ++i) {
    password += charset.charAt(Math.floor(Math.random() * n));
  }
  return password;
}

// Ask user for the master password
async function askMasterPassword() {
  masterPassword = prompt("Please enter your master password:");
  if (!masterPassword) {
    alert("Master password is required to use the password manager.");
  }
}

// Derive a key from the master password using PBKDF2
async function deriveKey(masterPassword) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw", 
    enc.encode(masterPassword), 
    { name: "PBKDF2" }, 
    false, 
    ["deriveKey"]
  );

  // Derive the key for AES-GCM
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode("unique-salt"), // This should be stored alongside the encrypted data
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypt the password with AES-GCM
async function encryptPassword(password) {
  const key = await deriveKey(masterPassword);
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Initialization vector
  const enc = new TextEncoder();

  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(password)
  );

  return {
    ciphertext: Array.from(new Uint8Array(ciphertext)),
    iv: Array.from(iv)
  };
}

// Decrypt the password with AES-GCM
async function decryptPassword(encryptedData) {
  const key = await deriveKey(masterPassword);
  const iv = new Uint8Array(encryptedData.iv);
  const ciphertext = new Uint8Array(encryptedData.ciphertext);
  
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    ciphertext
  );

  const dec = new TextDecoder();
  return dec.decode(decrypted);
}

// Event listener to generate the password
document.getElementById('generatePasswordButton').addEventListener('click', function() {
  const generatedPassword = generatePassword();
  document.getElementById('generatedPassword').value = generatedPassword;
  document.getElementById('password').value = generatedPassword;  // Auto-fill the password field with the generated password
});

// Save the password (encrypt before storing)
document.getElementById('passwordForm').addEventListener('submit', async function (e) {
  e.preventDefault();

  const website = document.getElementById('website').value;
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  if (!website || !username || !password || !masterPassword) {
    alert('Please fill in all fields and set a master password.');
    return;
  }

  const encryptedPassword = await encryptPassword(password);

  // Store encrypted password in Chrome storage
  chrome.storage.local.get({ passwords: [] }, function (result) {
    const passwords = result.passwords;
    passwords.push({ website, username, password: encryptedPassword });
    chrome.storage.local.set({ passwords }, function () {
      alert('Password saved securely!');
      document.getElementById('passwordForm').reset();
      displayPasswords();
    });
  });
});

// Display saved passwords (decrypt before displaying)
async function displayPasswords() {
  chrome.storage.local.get({ passwords: [] }, async function (result) {
    const passwords = result.passwords;
    const passwordList = document.getElementById('passwordList');
    passwordList.innerHTML = '';

    for (const entry of passwords) {
      const decryptedPassword = await decryptPassword(entry.password);
      const listItem = document.createElement('li');
      listItem.textContent = `Website: ${entry.website}, Username: ${entry.username}, Password: ${decryptedPassword}`;
      
      const deleteButton = document.createElement('button');
      deleteButton.textContent = 'Delete';
      deleteButton.addEventListener('click', function () {
        deletePassword(passwords.indexOf(entry));
      });

      listItem.appendChild(deleteButton);
      passwordList.appendChild(listItem);
    }
  });
}

// Delete password function
function deletePassword(index) {
  chrome.storage.local.get({ passwords: [] }, function (result) {
    const passwords = result.passwords;
    passwords.splice(index, 1);
    chrome.storage.local.set({ passwords }, function () {
      displayPasswords();
    });
  });
}

// Display passwords when the popup opens
document.addEventListener('DOMContentLoaded', askMasterPassword);
document.addEventListener('DOMContentLoaded', displayPasswords);
