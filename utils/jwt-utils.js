const crypto = require('crypto');

async function signJWT(payload, secret, expiresInSeconds=3600) {
    const header = JSON.stringify({alg: 'HS256', typ: 'JWT'});
    const currentTime = Math.floor(Date.now() / 1000);

    payload = {id: payload};
    payload.exp = currentTime + expiresInSeconds;

    payload = JSON.stringify(payload);
    const encodeHeader = Buffer.from(header).toString('base64url');
    const encodePayload = Buffer.from(payload).toString('base64url');

    const signature = crypto.createHmac('sha256', secret).update(`${encodeHeader}.${encodePayload}`).digest('base64url');
    const jwt = `${encodeHeader}.${encodePayload}.${signature}`;
    return jwt;
}

async function verifyJWT(token, secret) {
    const [header, payload, signature] = token.split('.');
    const verify = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');

    const decodePayload = Buffer.from(payload, 'base64url').toString('utf8');
    const parse = JSON.parse(decodePayload);
    const current = Math.floor(Date.now() / 1000);

    if (signature !== verify) {
        throw new Error('invalid token');
    }  

    if (parse.exp < current) {
        throw new Error('expired token');
    }
    return parse;
}

module.exports = { signJWT, verifyJWT };
