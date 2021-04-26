const jwtSecret = require('crypto').randomBytes(32) // aes256
const GITHUB_CLIENT_ID = '920e5b01a622fde12885'


module.exports = {jwtSecret: jwtSecret, GITHUB_CLIENT_ID: GITHUB_CLIENT_ID}