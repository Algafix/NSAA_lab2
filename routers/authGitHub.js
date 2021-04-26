const express = require('express');
const router = express.Router();
const passport = require('passport');
const generateCookie = require('../middlewares/cookieMiddleware');


router.get('/', passport.authenticate('github'));

router.get('/callback',
  passport.authenticate('github', { failureRedirect: '/login', session: false }),
  generateCookie,
  function(req, res) {
    res.redirect('/');
  }
);

module.exports = router




