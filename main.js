const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
require("dotenv").config();

const app = express();

// ===========================
// BODY PARSER MIDDLEWARE
// ===========================

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ===========================
// STATIC FILES
// ===========================

app.use(express.static("public"));

// ===========================
// VIEW ENGINE
// ===========================

app.set("view engine", "ejs");

// ===========================
// MONGODB CONNECTION
// ===========================

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB Connected Successfully");
  })
  .catch((err) => {
    console.log("MongoDB Connection Error:", err);
  });

// ===========================
// SESSION CONFIGURATION
// ===========================

app.use(session({

  secret: process.env.SESSION_SECRET,

  resave: false,

  saveUninitialized: false,

  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI
  }),

  cookie: {
  maxAge: 1000 * 60 * 60 * 24,
  httpOnly: true,
  secure: false
  }


}));
const User = require("./models/User");

app.use(async (req, res, next) => {

  if (req.session.userId) {

    const user = await User.findById(req.session.userId);

    res.locals.user = user;
  }

  next();
});


// ===========================
// ROUTES
// ===========================

const authRoutes = require("./routes/authRoutes");
const mainRoutes = require("./routes/mainRoutes");

app.use("/", authRoutes);
app.use("/", mainRoutes);

// ===========================
// SERVER START
// ===========================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running successfully`);
  console.log(`Open in browser: http://localhost:${PORT}`);
});

