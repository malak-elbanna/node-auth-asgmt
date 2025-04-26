const crypto = require('crypto');

async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex'); 
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    const hashed = `${salt}:${hash}`;
    return hashed;
}

async function verifyPassword(password, hashedPassword) {
    const [salt, hash] = hashedPassword.split(':'); 
    const verify = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash === verify;
}

module.exports = { hashPassword, verifyPassword };
