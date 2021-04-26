const jwt = require('jsonwebtoken')
const jwtSecret = require('../config').jwtSecret

function generateCookie(req, res, next) { 
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }
  
    const token = jwt.sign(jwtClaims, jwtSecret)
   
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  
    res.cookie('jwt_session', token)
  
    next()
}


module.exports = generateCookie



