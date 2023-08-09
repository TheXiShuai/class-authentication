// require session
const session = require('express-session');

// ADDED: require mongostore
const connectMongo = require('connect-mongo');

module.exports = app => {
    app.set('trust proxy', 1);

    app.use(
        session({
            secret: process.env.SESS_SECRET,
            resave: true,
            saveUninitialized: true,
            cookie: {
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                maxAge: 60000
            }, // ADDED code below !!!
            store: connectMongo.create({
                mongoUrl: process.env.MONGODB_URI

                // ttl => time to live
                // ttl: 60 * 60 * 24 // 60sec * 60min * 24h => 1 day
            })
        })
    );
};