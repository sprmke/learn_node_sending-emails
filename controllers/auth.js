const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const User = require('../models/user');

const getErrorMessage = (req) => {
  let errorMessage = req.flash('errorMessage');
  if (errorMessage.length > 0) {
    errorMessage = errorMessage[0];
  } else {
    errorMessage = null;
  }

  return errorMessage;
};

exports.getLogin = (req, res, next) => {
  const errorMessage = getErrorMessage(req);

  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage,
  });
};

exports.getSignup = (req, res, next) => {
  const errorMessage = getErrorMessage(req);

  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage,
  });
};

exports.postLogin = (req, res, next) => {
  const { email, password } = req.body;

  User.findOne({ email })
    .then((user) => {
      if (!user) {
        req.flash('errorMessage', 'Invalid email or password.');
        return req.session.save((error) => {
          return res.redirect('/login');
        });
      }

      // validate password
      bcrypt
        .compare(password, user.password)
        .then((isMatched) => {
          if (isMatched) {
            // save session info
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save((err) => {
              res.redirect('/');
            });
          }

          req.flash('errorMessage', 'Invalid email or password.');
          return req.session.save((err) => {
            res.redirect('/login');
          });
        })
        .catch((err) => {
          console.log(err);
          res.redirect('/login');
        });
    })
    .catch((err) => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const { email, password, confirmPassword } = req.body;

  // add validation here

  User.findOne({ email })
    .then((user) => {
      // if user email already exist, redirect to signup page
      if (user) {
        req.flash('errorMessage', 'Email already exists.');
        return req.session.save((error) => {
          res.redirect('/signup');
        });
      }

      // encrypt password
      return bcrypt
        .hash(password, 12)
        .then((encryptedPassword) => {
          // create new user
          const user = new User({
            email,
            password: encryptedPassword,
            cart: { items: [] },
          });

          return user.save();
        })
        .then(async (result) => {
          return await sendEmailWithEtherialService();
        })
        .then((result) => res.redirect('/login'));
    })
    .catch((err) => {
      console.log(err);
      req.flash('errorMessage', 'Email is required.');
      return req.session.save((error) => {
        res.redirect('/signup');
      });
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.log(err);
    res.redirect('/');
  });
};

const sendEmailWithEtherialService = async () => {
  // Generate test SMTP service account from ethereal.email
  // Only needed if you don't have a real mail account for testing
  let testAccount = await nodemailer.createTestAccount();

  // create reusable transporter object using the default SMTP transport
  let transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
      user: testAccount.user, // generated ethereal user
      pass: testAccount.pass, // generated ethereal password
    },
  });

  // send mail with defined transport object
  let info = await transporter.sendMail({
    from: '"Mike Cutie 👻" <mike@cutie.com>', // sender address
    to: 'bojecof901@dicopto.com', // list of receivers
    subject: 'Hello there! ✔', // Subject line
    text: 'Hello world?', // plain text body
    html: '<b>Hello world?</b>', // html body
  });

  console.log('Message sent: %s', info.messageId);
  // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>

  // Preview only available when sending through an Ethereal account
  console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
  // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...

  return info;
};
