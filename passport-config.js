/* This file is where we store all passport related information */

const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

function initialize(passport, getUserByEmail, getUserById) {
  // done means we call this function when we are done authenticating our user (in this case)
  const authenticateUser = async (email, password, done) => {
    const user = getUserByEmail(email);
    // if the user email is not recognized, return message
    if (user == null) {
      return done(null, false, { message: "No user with that email" });
    }
    // since the function is asynchronous, we surround it in try-catch blocks
    try {
      // if the user's password matches the password in the parameter, return the user which we authenticated
      if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
      }
      // if password doesnt match, dont return user, return message instead
      else {
        return done(null, false, { message: "Password incorrect" });
      }
      // if there's an error, return the error
    } catch (error) {
      return done(error);
    }
  };
  passport.use(new LocalStrategy({ usernameField: "email" }, authenticateUser));
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    return done(null, getUserById(id));
  });
}

module.exports = initialize;
