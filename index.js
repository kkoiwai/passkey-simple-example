
import { JSONFilePreset } from 'lowdb/node'
const db = await JSONFilePreset('db.json', { credentials: [], users: [] })
const { credentials, users } = db.data

import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL }
    from '@simplewebauthn/server/helpers';


import express from 'express';
import session from 'express-session';
import useragent from 'express-useragent';
import path from 'path';

const app = express();
app.use(session({
    secret: 'use passkey!',
    resave: true,
    saveUninitialized: true,
    cookie: { maxAge: 60000 }
}));
app.use(express.json());
app.use(useragent.express());

const port = 3000;
const RPID = "localhost";
const ORIGIN = "http://localhost:3000";

app.get('/registerRequest', async (req, res) => {

    if (!req.query.username || req.query.username.trim().length === 0) {
        return res.status(400).send({ error: "username empty" });
    }
    const username = req.query.username.trim();

    req.session.user = { id: username };

    const options = await generateRegistrationOptions({
        rpName: "Example Website",
        // rpID: "example.com",
        rpID: RPID,
        userName: username,
        timeout: 300000,
        excludeCredentials: [],
    });

    req.session.challenge = options.challenge;
    return res.json(options);
});

app.post('/registerResponse', async (req, res) => {

    const expectedChallenge = req.session.challenge;
    // const expectedOrigin = `https://example.com`
    // const expectedRPID = "example.com";
    const expectedOrigin = ORIGIN;
    const expectedRPID = RPID;
    // const credential = req.body;

    console.log(req.body);
    try {
        const verification =
            await verifyRegistrationResponse({
                response: req.body, // (d1)
                expectedChallenge, // (d2)
                expectedOrigin, // (d3)
                expectedRPID, // (d4)
                requireUserVerification: false // (d5)
            });

        const { verified, registrationInfo } =
            verification;

        if (!verified) {
            throw new Error('User verification failed.');
        }

        console.log(registrationInfo);
        const { credential, userVerified } =
            registrationInfo;
        const base64PublicKey =
            isoBase64URL.fromBuffer(credential.publicKey);
        const { user } = req.session;
        console.log(user);

        const cred = { // (d6)
            id: credential.id,
            publicKey: base64PublicKey,
            name: req.useragent.platform,
            registered: (new Date()).getTime(),
            last_used: null,
            user_id: user.id
        };
        // データベースに保存
        await db.update(({ credentials }) => credentials.push(cred));

        await db.update(({ users }) => users.push(user));

        return res.json({ status: "success" });
    } catch (e) {
        console.error(e)
        return res.status(400).send({ error: e.message });
    } finally {
        delete req.session.challenge; // (d7)
    }
});

app.get('/signinRequest', async (req, res) => {

    var allowCredentials = [];
    if (req.query.username && req.query.username.trim().length > 0) {
        const username = req.query.username.trim();
        const creds = credentials.filter((cred) => cred.user_id === username);
        allowCredentials = creds.map(cred => ({ id: cred.id }))
    }

    const options = await generateAuthenticationOptions({
        rpID: RPID,
        allowCredentials,
        timeout: 60000,
    });

    req.session.challenge = options.challenge;
    return res.json(options);
});


app.post('/signinResponse', async (req, res) => {

    const credential = req.body;
    const expectedChallenge = req.session.challenge;
    // const expectedOrigin = `https://example.com`;
    // const expectedRPID = 'example.com';
    const expectedOrigin = ORIGIN;
    const expectedRPID = RPID;

    // console.log(req.body);
    try {
        const cred =
            credentials.find((cred) => cred.id === credential.id); // (d1)
        if (!cred) {
            throw new Error(
                'Matching credential not found on the server.');
        }

        const user =
            users.find((user) => user.id === cred.user_id); // (d2)
        if (!user) {
            throw new Error('User not found.');
        }

        const authenticator = {
            publicKey: isoBase64URL.toBuffer(
                cred.publicKey),
            id: isoBase64URL.toBuffer(cred.id)
        };

        const verification =
            await verifyAuthenticationResponse({
                response: credential, // (d3)
                expectedChallenge, // (d4)
                expectedOrigin, // (d5)
                expectedRPID, // (d6)
                credential: authenticator,
                requireUserVerification: false // (d7)
            });

        const { verified, authenticationInfo } =
            verification;

        const { userVerified } = authenticationInfo;

        if (!verified) {
            throw new Error('User verification failed.');
        }

        // Update the last used timestamp.
        await db.update(({ credentials }) => {
            credentials.find((cred) =>
                cred.id === credential.id).last_used = (new Date()).getTime()
        }); // (d8)

        req.session.username = user.username;
        req.session['signed-in'] = 'yes';

        return res.json({ status: "success" }); // (d9)
    } catch (e) {
        console.log(e);
        return res.status(400).json({ error: e.message });
    } finally {
        delete req.session.challenge; // (d10)
    }
});



app.get('/', (req, res) => {
    res.sendFile(path.join(import.meta.dirname, "public", '/index.html'));
});
app.get('/polyfill.js', (req, res) => {
    res.sendFile(path.join(import.meta.dirname, "public", '/polyfill.js'));
});



app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});