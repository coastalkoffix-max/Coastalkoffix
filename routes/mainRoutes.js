const express = require("express");
const router = express.Router();

// Middleware
const isLoggedIn = (req, res, next) => {

  if (req.session.userId) {
    return res.redirect("/home");
  }

  next();
};

const isAuth = (req, res, next) => {

  if (!req.session.userId) {
    return res.redirect("/login");
  }

  next();
};

// Root Route
router.get("/", isLoggedIn, (req, res) => {
  res.redirect("/login");
});

// Home Route
router.get("/home", isAuth, (req, res) => {
  res.render("home");
});
router.get("/profile", isAuth, async (req, res) => {

  const user = res.locals.user;

  res.render("profile", { user });

});

module.exports = router;
