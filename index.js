const path = require('path')
const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')


const GitHubRouter = require('./routers/authGitHub')
const genCookie = require('./middlewares/cookieMiddleware')
const strategies = require('./passportStrats')


// ----------------------------------------------------------- //
// ---------------------- APP CONFIG ------------------------- //
// ----------------------------------------------------------- //

const port = 3000

const app = express()
app.use(logger('dev'))
app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.
app.use(cookieParser());



// ----------------------------------------------------------- //
// ---------------------- STRATEGIES-------------------------- //
// ----------------------------------------------------------- //

passport.use('local_login', strategies.localStrat)

passport.use('jwt_auth', strategies.jwtStrat)

passport.use(strategies.gitHubOAuth)

passport.use('radius', strategies.radiusStrat)


// ----------------------------------------------------------- //
// ---------------------- ROUTES ----------------------------- //
// ----------------------------------------------------------- //

app.use('/auth/github', GitHubRouter)

// ----------------------- ROOT ------------------------------ //

/**
 * If the JWT auth is correct, sends a fortune along with the user name extracted
 * from the cookie and appended to the request in the jwt_auth middleware.
 * If the JWT auth is incorrect, redirects to the login page.
 */
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
    res.sendFile(path.join(__dirname, '/views/login.html'))
})

app.post('/login',
  passport.authenticate('local_login', { failureRedirect: '/login', session: false }),
  genCookie,
  (req, res) => {
    res.redirect('/')
  }
)

app.get('/login_radius', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login_radius.html'))
})

app.post('/login_radius',
  passport.authenticate('radius', { failureRedirect: '/login', session: false }),
  genCookie,
  (req, res) => {
      res.redirect('/')
  }
)


// ----------------------- LOGOUT----------------------------- //

/**
 * Deletes the cookie (the session) and redirects to the main page.
 */
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
