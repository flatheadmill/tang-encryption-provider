const assert = require('assert')

const axios = require('axios')
const jose = require('jose')

const thp = 'o6U9qKv0_XdugefJV3q_NknYTY4Xgw27kcUnErkrVCY'
const url = 'http://tang:8080'

async function main () {
    const response = await axios.get(`${url}/adv/${thp}`)
    let jws = response.data
    let jwks = JSON.parse(Buffer.from(jws.payload, 'base64').toString())
    let ver = jwks.keys.filter(key => key.key_ops.includes('verify')).shift()
    let ever = await jose.importJWK(ver)
    await jose.generalVerify(jws, ever)
    assert.equal(await jose.calculateJwkThumbprint(ver), thp)
    let jwk = jwks.keys.filter(key => key.key_ops.includes('deriveKey')).shift()
    let ejwk = await jose.importJWK(jwk)
    delete jwk.key_ops
    delete jwk.alg
    let kid = await jose.calculateJwkThumbprint(jwk)
    let jwe = {
        protected: {
            alg: 'ECDH-ES',
            enc: 'A256GCM',
            clevis: {
                pin: 'tang',
                tang: {
                    url: url,
                    adv: jwks
                }
            },
            kid: kid
        }
    }
    let ctxt = await new jose.CompactEncrypt(
        new TextEncoder().encode('hi\n')
    ).setProtectedHeader(jwe.protected).encrypt(ejwk)
    console.log(ctxt)
}

main()
