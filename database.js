const bcrypt = require('bcrypt')
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


module.exports = db

