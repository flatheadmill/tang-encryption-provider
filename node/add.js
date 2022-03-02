//const assert = require('assert')

const fs = require('fs').promises

const base64url = require('base64url')
const EC = require('elliptic').ec
const ecKeyUtils = require('eckey-utils')
const jose = require('jose')
const axios = require('axios')
const getStdin = require('get-stdin')
const crypto = require('crypto')

const thp = 'o6U9qKv0_XdugefJV3q_NknYTY4Xgw27kcUnErkrVCY'
const url = 'http://tang:8080'

async function main () {
    let lcl = JSON.parse(await fs.readFile('clt.json', 'utf8'))
    lcl = crypto.createPublicKey({ key: lcl, format: 'jwk' })
    lcl = ecKeyUtils.parsePem(lcl.export({ type: 'spki', format: 'pem' }).trim())
    let rem = JSON.parse(await fs.readFile('rem.json', 'utf8'))
    rem = crypto.createPrivateKey({ key: rem, format: 'jwk' })
    rem = ecKeyUtils.parsePem(rem.export({ format: 'pem', type: 'sec1' }).trim())
    let ec = new EC('p521')
    lcl = ec.keyFromPublic(lcl.publicKey)
    rem = ec.keyFromPrivate(rem.privateKey)
    let exc = lcl.getPublic().add(rem.getPublic())
    console.log('x:', base64url(exc.getX().toBuffer()))
    console.log('y:', base64url(exc.getY().toBuffer()))
    let pem = ecKeyUtils.generatePem({
        curveName: 'secp521r1',
        publicKey: Buffer.from(exc.encode(false, 'hex'))
    })
    const ecPublicKey = await jose.importSPKI(pem.publicKey)
    console.log(await jose.exportJWK(ecPublicKey))
}

main()
