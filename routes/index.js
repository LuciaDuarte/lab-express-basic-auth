const { Router } = require('express');
const router = Router();
const bcrypt = require('bcryptjs');

const User = require('./../models/user');
const routeAuthenticationGuard = require('./../middleware/route-authentication-guard');

router.get('/', (request, response, next) => {
  response.render('index');
});

router.get('/sign-up', (request, response, next) => {
  response.render('authentication/sign-up');
});

router.post('/sign-up', (request, response, next) => {
  const { username, password } = request.body;

  bcrypt
    .hash(password, 10)
    .then(hashAndSalt => {
      return User.create({
        username,
        password: hashAndSalt
      });
    })
    .then(user => {
      request.session.userId = user._id;
      response.redirect('/');
    })
    .catch(error => {
      next(error);
    });
});

router.get('/sign-in', (request, response, next) => {
  response.render('authentication/sign-in');
});

router.post('/sign-in', (request, response, next) => {
  const { username, password } = request.body;

  let user;

  User.findOne({ username })
    .then(document => {
      user = document;
      if (!user) {
        return Promise.reject(new Error('No user with that username.'));
      }
      const passwordHashAndSalt = user.password;
      return bcrypt.compare(password, passwordHashAndSalt);
    })
    .then(comparison => {
      if (comparison) {
        // User username and password are correct
        request.session.userId = user._id;
        response.redirect('/');
      } else {
        // User username and password are wrong.
        const error = new Error('Password did not match.');

        return Promise.reject(error);
      }
    })
    .catch(error => {
      next(error);
    });
});

router.get('/private', routeAuthenticationGuard, (request, response, next) => {
  response.render('private');
});

router.get('/main', routeAuthenticationGuard, (request, response, next) => {
  response.render('main');
});

module.exports = router;
