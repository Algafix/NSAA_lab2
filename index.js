const path = require('path')
const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const jwtSecret = require('crypto').randomBytes(32) // aes256
const bcrypt = require('bcrypt')



// ----------------------------------------------------------- //
// ------------------------ DB INIT -------------------------- //
// ----------------------------------------------------------- //

const JsonDB = require('node-json-db').JsonDB
const DBConfig = require('node-json-db/dist/lib/JsonDBConfig').Config
const db = new JsonDB(new DBConfig("usersDB", true, true, '/'));

// Just for testing, (obviously) not secure

addUser = function(user) {
  return function(err, hashedPWD) {
    if (err) {
      console.log("Error hashing the password.", err)
    } else {
      db.push("/"+user, {username: user, password: hashedPWD});
    }
  }
}

// bcrypt.hash(myPlaintextPassword, saltRounds, function(err, hash)
bcrypt.hash('walruspassword', 10, addUser('walrus'))
bcrypt.hash('aleixpassword', 10, addUser('aleix'))
bcrypt.hash('nsaapassword', 10, addUser('nsaa'))



// ----------------------------------------------------------- //
// ---------------------- APP CONFIG ------------------------- //
// ----------------------------------------------------------- //

const port = 3000

// express as a function returns an app
const app = express()
app.use(logger('dev'))
app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.
app.use(cookieParser());



// ----------------------------------------------------------- //
// ---------------------- STRATEGIES-------------------------- //
// ----------------------------------------------------------- //

/*
Configure the local strategy for use by Passport.
The local strategy requires a `verify` function which receives the credentials
(`username` and `password`) submitted by the user.  The function must verify
that the username and password are correct and then invoke `done` with a user
object, which will be set at `req.user` in route handlers after authentication.
*/
passport.use('local_login', new LocalStrategy(
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
))

passport.use('jwt_auth', new JwtStrategy(
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
))



// ----------------------------------------------------------- //
// ---------------------- ROUTES ----------------------------- //
// ----------------------------------------------------------- //


// ----------------------- ROOT ------------------------------ //

app.get('/',
  passport.authenticate('jwt_auth', {failureRedirect: '/login', session: false}),
  (req, res) => {
    res.send(
      "<h1>Howdy, " + req.user + "!</h1>" + 
      fortune.fortune() + 
      "<br><br><a href='/'>Another one!</a>" + 
      "<br><br><a href='/logout'>Logout</a>"
    )
})


// ----------------------- LOGIN ----------------------------- //

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'))
})

app.post('/login',
  passport.authenticate('local_login', { failureRedirect: '/login', session: false }),
  (req, res) => { //
    // we should create here the JWT for the fortune teller and send it to the user agent inside a cookie.
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // Just for testing, send the JWT directly to the browser. Later on we should send the token inside a cookie.
    //res.json(token)
    
    res.cookie('jwt_session', token)

    res.redirect('/')

    // And let us log a link to the jwt.iot debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)


// ----------------------- LOGOUT----------------------------- //

app.get('/logout', (req, res) => {
  res.clearCookie('jwt_session')
  res.redirect('/')
})


// ----------------------- ERROR ----------------------------- //

app.use(function (err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
})



// ----------------------------------------------------------- //
// ------------------------- START --------------------------- //
// ----------------------------------------------------------- //

app.listen(port, () => {
    console.log(`Listening at http://localhost:${port}`)
})


// Create a middleware
// const myLogger = (req, res, next) => {
//     console.log(req)
//     next()
// }

// Register a middleware for all the endpoints
//app.use(myLogger)
