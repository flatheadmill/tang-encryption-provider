//const assert = require('assert')

const fs = require('fs').promises

const { callback } = require('comeuppance')
const base64url = require('base64url')
const EC = require('elliptic').ec
const ecKeyUtils = require('eckey-utils')
const jose = require('jose')
const cisco = require('node-jose')
const axios = require('axios')
const getStdin = require('get-stdin')
const crypto = require('crypto')

const thp = 'o6U9qKv0_XdugefJV3q_NknYTY4Xgw27kcUnErkrVCY'
const url = 'http://tang:8080'

function getPublicKey (ec, key) {
    const jwk = crypto.createPublicKey({ key: key, format: 'jwk' })
    const asn1 = ecKeyUtils.parsePem(jwk.export({ type: 'spki', format: 'pem' }).trim())
    return { key: jwk, ec: ec.keyFromPublic(asn1.publicKey) }
}

function getPrivateKey (ec, key) {
    const asn1 = ecKeyUtils.parsePem(key.export({ type: 'sec1', format: 'pem' }).trim())
    return { key: key, ec: ec.keyFromPrivate(asn1.privateKey) }
}

async function geneatePrivateKey (ec) {
    const [ _, key ] = await callback(callback => crypto.generateKeyPair('ec', { namedCurve: 'secp521r1' }, callback))
    console.log(key)
    return getPrivateKey(ec, key)
}

function keyFromPoint (ec, point) {
    const pem = ecKeyUtils.generatePem({
        curveName: 'secp521r1',
        publicKey: Buffer.from(point.encode(false, 'hex'))
    })
    const key = crypto.createPublicKey({ key: pem.publicKey, format: 'pem' })
    const asn1 = ecKeyUtils.parsePem(key.export({ type: 'spki', format: 'pem' }).trim())
    return { key: key, ec: ec.keyFromPublic(asn1.publicKey) }
}

async function main () {
    let hdr = await getStdin()
    const header = jose.decodeProtectedHeader(hdr)
    const ec = new EC('p521')
    const local = getPublicKey(ec, header.epk)
    let sought
    for (const key of header.clevis.tang.adv.keys) {
        if (await jose.calculateJwkThumbprint(key) == header.kid) {
            sought = key
            break
        }
    }
    const remote = getPublicKey(ec, sought)
    let eph = JSON.parse(await fs.readFile('eph.json', 'utf8'))
    eph = crypto.createPrivateKey({ key: eph, format: 'jwk' })
    const ephemeral = await getPrivateKey(ec, eph)
    const exchange = local.ec.getPublic().add(ephemeral.ec.getPublic())
    const pem = ecKeyUtils.generatePem({
        curveName: 'secp521r1',
        publicKey: Buffer.from(exchange.encode(false, 'hex'))
    })
    const ecmr = await jose.exportJWK(await jose.importSPKI(pem.publicKey))
    const response = getPublicKey(ec, (await axios.post(`${url}/rec/${header.kid}`, ecmr, {
        headers: {
            'Content-Type': 'application/jwk+json'
        }
    })).data)
    const temp = keyFromPoint(ec, remote.ec.getPublic().mul(ephemeral.ec.getPrivate()))
    const point = response.ec.getPublic().add(temp.ec.getPublic().neg())
    const jwk_ = keyFromPoint(ec, point)
    const raw = jwk_.key.export({ format: 'jwk' })

    // Left off at key definition.
}

main()
