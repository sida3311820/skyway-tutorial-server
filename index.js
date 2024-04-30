const jwt = require('jsonwebtoken');
const express = require('express');
const crypto = require('crypto');

const id = process.env.ID;
const secret = process.env.SECRET;

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((_, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

app.post('/authenticate', (req, res) => {
    const channelName = req.body.channelName;
    const memberName = req.body.memberName;
    const sessionToken = req.body.sessionToken;

    if (channelName === undefined || memberName === undefined || sessionToken === undefined) {
        res.status(400).send('Bad Request');
        return;
    }

    // Check the sessionToken for your app.
    if (sessionToken != process.env.SESSION_TOKEN) {
        console.log('auth fail!')
        res.status(401).send('Authentication Failed');
    }

    const iat = Math.floor(Date.now() / 1000);
    const exp = Math.floor(Date.now() / 1000) + 36000; // 10h=60*60*10

    const credential = {
        channelName: channelName,
        memberName: memberName,
        iat: iat,
        exp: exp,
        authToken: calculateAuthToken(channelName, memberName, iat, exp)
    };

    res.send(credential);
});

const listener = app.listen(process.env.PORT || 8080, () => {
    console.log(`Server listening on port ${listener.address().port}`)
});

const calculateAuthToken = (channelName, memberName, iat, exp) => {
    return jwt.sign({
        jti: crypto.randomUUID(),
        iat: iat,
        exp: exp,
        scope: {
            app: {
                id: id,
                turn: true,
                analytics: true,
                actions: ['read'],
                channels: [
                    {
                        id: '*',
                        name: '*',
                        actions: ['write'],
                        members: [
                            {
                                id: '*',
                                name: '*',
                                actions: ['write'],
                                publication: {
                                    actions: ['write'],
                                },
                                subscription: {
                                    actions: ['write'],
                                },
                            },
                        ],
                        sfuBots: [
                            {
                                actions: ['write'],
                                forwardings: [
                                    {
                                        actions: ['write'],
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
        }
    }, secret);
};
