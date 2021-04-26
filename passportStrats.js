const passport = require("passport");
const bcrypt = require('bcrypt')
const JwtStrategy = require('passport-jwt').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const LocalStrategy = require('passport-local').Strategy;

const db = require('./database')
const jwtSecret = require('./config').jwtSecret;
const GITHUB_CLIENT_ID = require('./config').GITHUB_CLIENT_ID
const GITHUB_CLIENT_SECRET = require('./secrets').GITHUB_CLIENT_SECRET



/*
Configure the local strategy for use by Passport.
The local strategy requires a `verify` function which receives the credentials
(`username` and `password`) submitted by the user.  The function must verify
that the username and password are correct and then invoke `done` with a user
object, which will be set at `req.user` in route handlers after authentication.
*/
localStrat = new LocalStrategy(
    {
      usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
      passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
      session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's stateless
    },
    (username, password, done) => {
      try {
        var dbUser = db.getData('/' + username)
        bcrypt.compare(password, dbUser.password, (err, result) => {
          if (err) {
            return done(err, false)
          }
          if (result) {
            const user = { 
              username: dbUser.username,
              description: 'A nice user'
            }
            return done(null, user)
          }
          return done(null, false)
        })
      } catch(error) {
        return done(null, false)
      }
    }
)

/**
 * Configure the JWT authentication strategy.
 * Sets the key used to compute abría incluido los the HMAC and defines a function to extract the JWT
 * from the request (in our case, stored in the cookies).
 * Then we specify the verify function that will be called if the verification
 * is correct. jwt_payload contains the content of que JWT.
 */
jwtStrat = new JwtStrategy(
    {
      secretOrKey: jwtSecret,
      jwtFromRequest: (req) => {
        return req.cookies.jwt_session
      }
    },
    (jwt_payload, done) => {
      if(jwt_payload) {
        return done(null, jwt_payload.sub)
      }
      return done(null, false)
    }
)


gitHubStrat = new GitHubStrategy(
    {
      clientID: GITHUB_CLIENT_ID,
      clientSecret: GITHUB_CLIENT_SECRET,
      callbackURL: "http://127.0.0.1:3000/auth/github/callback"
    },
    function(accessToken, refreshToken, profile, done) {
      user = {githubId: profile.id, username: profile.username}
      return done(null, user);
    }
)


module.exports = {
    gitHubOAuth: gitHubStrat,
    jwtStrat: jwtStrat,
    localStrat: localStrat
}


