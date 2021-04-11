
Express with password
=====================


Exchange the JWT using cookies
------------------------------

To exchange the JWT using cookies we first have to set the cookie parser middleware:

```javascript
const cookieParser = require('cookie-parser')
app.use(cookieParser());
```

Then we can get and set the cookie as a property of the request and response. We could authenticate the cookies providing a secret and then using the `signedCookies` method. However, are already using an authenticated JWT so it is not necessary.

```javascript
res.cookie('jwt_session', token)
req.cookies.jwt_session
```

The redirection to the main page is straightforward with:

```javascript
res.redirect('/')
```

Create the fortune-teller endpoint
----------------------------------

The fortune-teller endpoint should show an addage if the cookie is correct (the user has logged in) or redirect to the login page if not.

To verify the cookie we will use the passport-jwt strategy. In this strategy we need to define an ```options``` object with the secret used to create the JWT and how the JWT is retrieved (from the cookie in our case). And we also have to define a ```verify``` function that will be called as a middleware if the verification is correct.

```javascript
const JwtStrategy = require('passport-jwt').Strategy

passport.use('jwt_auth', new JwtStrategy(
  { // options
    secretOrKey: jwtSecret,
    jwtFromRequest: (req) => {
      return req.cookies.jwt_session
    }
  },// verify function
  (jwt_payload, done) => {
    if(jwt_payload) {
      return done(null, jwt_payload.sub)
    }
    return done(null, false)
  }
))
```

And then we are ready to use this middleware in the ```/``` endpoint, redirecting to ```/login``` if the verification fails.

```javascript
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
```

Add a logout endpoint
---------------------

The logout endpoint is straightforward. Because the server is completely stateless, the only thing storing the session is the cookie, so signaling the browser to delete it is enough to logout the user.

```javascript
app.get('/logout', (req, res) => {
  res.clearCookie('jwt_session')
  res.redirect('/')
})
```

Add bcrypt or scrypt to the login process
-----------------------------------------

We decided to use bcrypt for the password hashing and store the passwords in a formatted json file. For a lightweight PoC a complete database seemed overkill.

For the database we used the ```node-json-database``` package with the most easy configuration. The DB objects are stored in the ```usersDB.json``` file, to create a new object we use  ```db.push("path", {object})``` and to retrieve it ```db.getData("path")```.

To hash the passwords for every user we have used the asynchronous hash function of the ```bcrypt``` packet (it is less CPU blocking than the synchronous one). For this PoC we create the DB with 3 users and hashed passwords every time the app starts. Obviously, in a development scenario, a sing-up endpoint must exist that handles the user registration.

At the end, the database configuration lay as:


```javascript
const JsonDB = require('node-json-db').JsonDB
const DBConfig = require('node-json-db/dist/lib/JsonDBConfig').Config
const db = new JsonDB(new DBConfig("usersDB", true, true, '/'));

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
```

Then, when the user login we must compare the provided password with the one stored in the DB using the passport's local strategy. To do so, we also use the asynchronous check function provided by the bcrypt package.

```javascript
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
```

The ```try/catch``` block is there to detect if the user is not in the DB.



