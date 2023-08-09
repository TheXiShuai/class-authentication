//----------------- ALL THE REQUIRES HERE ------------------
const express = require('express');
const User = require('../models/User.model');
const router = express.Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const mongoose = require('mongoose')

// --------------------- ALL THE ROUTES HERE ---------------------
router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  // WE DESTUCTURE THE BODY AND WE HAVE DIFFERNT VARIABLES
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    res.render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
    return;
  }

  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({
        username,
        email,
        // if our variable name is different from the one in the model we can do this:
        passwordHash: hashedPassword
      })
    })
    .then(userFromDB => {
      console.log('Newly created user is: ', userFromDB);
      res.redirect("/userProfile");
    })
    .catch(error => {
      // copy the following if-else statement
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render('auth/signup', { errorMessage: error.message });
      } else {
        next(error);
      }
    });
})

router.get("/userProfile", (req, res) => {
  res.render("users/user-profile", { userInSession: req.session.currentUser })
})

router.get("/login", (req, res) => {
  res.render('auth/login')
})

router.post("/login", (req, res, next) => {
  const { username, password } = req.body;
  console.log('SESSION =====> ', req.session);

  if (username === '' || password === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter both, email and password to login.'
    });
    return;
  }

  User.findOne({ username })
    .then(user => {
      if (!user) {
        console.log("Username not registered. ");
        res.render('auth/login', { errorMessage: 'User not found' });
        return;
      } else if (bcryptjs.compareSync(password, user.passwordHash)) {

        req.session.currentUser = user;
        res.redirect('/userProfile');
      } else {
        console.log("Incorrect password. ");
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));
})

router.post("/logout", (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
})

module.exports = router;