if (process.env.NODE_ENV !== "production") {
  require("dotenv").config(); // loads in all environment variables and sets them inside of process.env
}

const express = require("express"); // imports Express, allows us to build web applications
const app = express(); // gets app variable from Express
const bcrypt = require("bcrypt"); // allows us to hash passwords and compare hashed passwords to make sure app is secure
const passport = require("passport"); // passport variable from Passport library
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override"); // allows us to override POST method to call delete method instead
const initializePassport = require("./passport-config");

initializePassport(
  passport,
  (email) =>
    // finds the user based on the email
    users.find((user) => user.email === email),
  (id) => users.find((user) => user.id === id)
);

const users = [];

app.set("view-engine", "ejs"); // tells our server we are using EJS so we can use EJS syntax

app.use(express.static("public")); // tells Express to look to the public folder for stylesheets

/* tells our app we want to take forms from email & password fields and be able to access them in our post() methods
below inside our req variable */
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    // key which encrypts all our info
    secret: process.env.SESSION_SECRET,
    // should we resave our session variables if nothing has changed?
    resave: false,
    // should we save an empty value of the session?
    saveUninitialized: false,
  })
);

app.use(passport.initialize());

// stores our variables across the entire session a user has
app.use(passport.session());

app.use(methodOverride("_method"));

// get function sets up the route for the application to render
app.get("/", checkAuthenticated, (req, res) => {
  // req = request, res = response
  res.render("index.ejs", { name: req.user.name }); // telling the app which page we want to render and passing a name option down
});

app.get("/login", checkNotAuthenticated, (req, res) => {
  res.render("login.ejs");
});

app.post(
  "/login",
  checkNotAuthenticated,
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true, // allows us to have a flash message which we can display to user
  })
);

app.get("/register", checkNotAuthenticated, (req, res) => {
  res.render("register.ejs");
});

app.post("/register", checkNotAuthenticated, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    users.push({
      id: Date.now().toString(), // unique identifier for users
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    });
    res.redirect("/login"); // redirects user back to login page upon succesful registration
  } catch {
    res.redirect("/register"); // keeps user on registration page upon failure
  }
});

// logs out user and redirects them to the login page
app.delete("/logout", (req, res, next) => {
  req.logOut((error) => {
    if (error) {
      return next(error);
    }
    res.redirect("/login");
  });
});

// check if user is already authenticated and redirect them to the login page if they aren't
function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect("/login");
}

// check if user is already authenticated and redirect them to the home page if they are
function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}

app.listen(3000); // sets app to run on port 3000
