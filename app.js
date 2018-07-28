var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var app = express();
var flash = require('connect-flash');
var User = require('./models/user');
var bCrypt = require('bcrypt');

LocalStrategy = require('passport-local').Strategy;

var dbConfig = require('./db.js');
var mongoose = require('mongoose');
mongoose.connect(dbConfig.url);

// Configuring Passport
var passport = require('passport');
var expressSession = require('express-session');
app.use(expressSession({secret: 'mySecretKey'}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

var indexRouter = require('./routes/index')(passport);

passport.serializeUser(function (user, done) {
  done(null, user._id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use('login', new LocalStrategy({
  passReqToCallback : true
},
function(req, username, password, done) { 
  // check in mongo if a user with username exists or not
  User.findOne({ 'username' :  username },
    function(err, user) {
      // In case of any error, return using the done method
      if (err)
        return done(err);
      // Username does not exist, log error & redirect back
      if (!user){
        console.log('User Not Found with username '+username);
        return done(null, false,
              req.flash('message', 'User Not found.'));
            }
      // User exists but wrong password, log the error 
      if (!isValidPassword(user, password)){
        console.log('Invalid Password');
        return done(null, false,
            req.flash('message', 'Invalid Password'));
      }
      // User and password both match, return user from 
      // done method which will be treated like success
      return done(null, user);
    }
  );
}));

var isValidPassword = function(user, password){
  return bCrypt.compareSync(password, user.password);
}

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

passport.use('signup', new LocalStrategy({
  passReqToCallback : true
},
function(req, username, password, done) {
  findOrCreateUser = function(){
    // find a user in Mongo with provided username
    User.findOne({'username':username},function(err, user) {
      // In case of any error return
      if (err){
        console.log('Error in SignUp: '+err);
        return done(err);
      }
      // already exists
      if (user) {
        console.log('User already exists');
        return done(null, false, 
           req.flash('message','User Already Exists'));
      } else {
        // if there is no user with that email
        // create the user
        var newUser = new User();
        // set the user's local credentials
        newUser.username = username;

        // hash the password
        const saltRounds = 10;
        var salt = bCrypt.genSaltSync(saltRounds);
        var hash = bCrypt.hashSync(password, salt);
        newUser.password = hash
        newUser.email = req.param('email');
        newUser.gender = req.param('gender');
        newUser.address = req.param('address');

        // save the user
        newUser.save(function(err) {
          if (err){
            console.log('Error in Saving user: '+err);  
            throw err;  
          }
          console.log('User Registration succesful');    
          return done(null, newUser);
        });
      }
    });
  };
  // Delay the execution of findOrCreateUser and execute 
  // the method in the next tick of the event loop
  process.nextTick(findOrCreateUser);
  })
);

module.exports = app;
