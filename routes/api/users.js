const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");
const passport = require("passport");

//Load input validation]
const validationRegisterInput = require("../../validation/register");
const validationLoginInput = require("../../validation/login");

//Load user Model
const User = require("../../models/User");

//@route     GET api/users/test
//@descriptiion   Tests user routes
// @access Public
router.get("/test", (req, res) => res.json({ msg: "Users Works" }));

//@route     GET api/users/test
//@descriptiion   register user
// @access Public

router.post("/register", (req, res) => {
  const { errors, isValid } = validationRegisterInput(req.body);

  //check Validation

  if (!isValid) {
    return res.status(400).json(errors);
  }
  User.findOne({ email: req.body.email }).then((user) => {
    if (user) {
      errors.email = "Email Already Exists";
      return res.status(400).json(errors);
    } else {
      const avatar = gravatar.url(req.body.email, {
        s: "200", //Size
        r: "pg", //Rating
        d: "mm", //Default
      });
      const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        avatar,
        password: req.body.password,
      });
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          newUser
            .save()
            .then((user) => res.json(user))
            .catch((err) => console.log(err));
        });
      });
    }
  });
});

//@route     POSt api/users/login
//@descriptiion   login user/retruning token
// @access Public

router.post("/login", (req, res) => {
  const { errors, isValid } = validationLoginInput(req.body);

  //check Validation

  if (!isValid) {
    return res.status(400).json(errors);
  }
  const email = req.body.email;
  const password = req.body.password;

  // Find user By email
  User.findOne({ email }).then((user) => {
    //check
    if (!user) {
      errors.email = "User not found";
      return res.status(404).json(errors);
    }
    // Check Password
    bcrypt.compare(password, user.password).then((isMatch) => {
      if (isMatch) {
        // User Matched

        const payload = { id: user.id, name: user.name, avatar: user.avatar }; //create jwt payload

        //Sign Token
        jwt.sign(
          payload,
          keys.secretOrKey,
          { expiresIn: 3600 },
          (err, token) => {
            res.json({
              success: true,
              token: "Bearer " + token,
            });
          }
        );
      } else {
        errors.password = "Password in correct";
        return res.status(400).json(errors);
      }
    });
  });
});

//@route     GET api/users/current
//@descriptiion  Return current user
// @access Private

router.get(
  "/current",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
    });
  }
);

module.exports = router;
