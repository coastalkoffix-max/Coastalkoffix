const express = require("express");
const argon2 = require("argon2");
const nodemailer = require("nodemailer");

const User = require("../models/User");
const Otp = require("../models/Otp");

const router = express.Router();


// ===============================
// EMAIL CONFIG (PRODUCTION SAFE)
// ===============================
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true, // SSL

  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },

  pool: true,
  maxConnections: 2,
  maxMessages: 50,

  connectionTimeout: 20000,
  greetingTimeout: 20000,
  socketTimeout: 20000
});

transporter.verify()
  .then(() => console.log("SMTP Ready"))
  .catch(err => console.log("SMTP Error:", err));



// ===============================
// REGISTER PAGE
// ===============================

router.get("/register", (req, res) => {
  res.render("register");
});

// ===============================
// REGISTER FORM SUBMIT
// ===============================

router.post("/register", async (req, res) => {

  try {

    const {
      firstName,
      middleName,
      lastName,
      mobile,
      country,
      state,
      district,
      pinCode,
      email,
      password
    } = req.body;

    // PASSWORD VALIDATION
    const passwordRegex =
      /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{6,}$/;

    if (!passwordRegex.test(password)) {
      return res.send("Password rules not matched");
    }

    const userExists = await User.findOne({ email });

    if (userExists) {
      return res.send("Email already registered");
    }

    // HASH PASSWORD
    const hashedPassword = await argon2.hash(password);

    // SAVE USER
    const newUser = new User({
      firstName,
      middleName,
      lastName,
      mobile,
      country,
      state,
      district,
      pinCode,
      email,
      password: hashedPassword,
      isVerified: false
    });

    await newUser.save();

    // GENERATE OTP
    const otpCode = Math.floor(1000 + Math.random() * 9000).toString();

    await Otp.deleteMany({ email });

    const otpData = new Otp({
      email,
      otp: otpCode,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    await otpData.save();

    // SEND EMAIL (NON BLOCKING)
    transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Coastal Koffix OTP Verification",
      text: `Your OTP is ${otpCode}`
    })
      .then(() => console.log("Registration OTP sent"))
      .catch(err => console.error("Email Error:", err));

    // FAST RESPONSE
    res.redirect(`/verify-otp?email=${email}`);

  } catch (error) {
    console.error(error);
    res.send("Registration failed. Try again.");
  }

});

// ===============================
// VERIFY OTP PAGE
// ===============================

router.get("/verify-otp", (req, res) => {
  res.render("verifyOtp", { email: req.query.email });
});

// ===============================
// VERIFY OTP
// ===============================

router.post("/verify-otp", async (req, res) => {

  try {

    const { email, otp } = req.body;

    const otpRecord = await Otp.findOne({ email, otp });

    if (!otpRecord) {
      return res.send("Invalid OTP");
    }

    if (otpRecord.expiresAt < new Date()) {
      return res.send("OTP Expired");
    }

    await User.updateOne(
      { email },
      { $set: { isVerified: true } }
    );

    await Otp.deleteMany({ email });

    const user = await User.findOne({ email });

    req.session.userId = user._id;

    res.redirect("/home");

  } catch (error) {
    console.error(error);
    res.send("OTP verification failed");
  }

});

// ===============================
// LOGIN PAGE
// ===============================

router.get("/login", (req, res) => {
  res.render("login");
});

// ===============================
// LOGIN
// ===============================

router.post("/login", async (req, res) => {

  try {

    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) return res.send("User not found");

    if (!user.isVerified) {
      return res.send("Please verify OTP first");
    }

    const isMatch = await argon2.verify(user.password, password);

    if (!isMatch) return res.send("Incorrect password");

    req.session.userId = user._id;

    res.redirect("/home");

  } catch (error) {
    console.error(error);
    res.send("Login failed");
  }

});

// ===============================
// FORGOT PASSWORD PAGE
// ===============================

router.get("/forgot-password", (req, res) => {
  res.render("forgotPassword");
});

// ===============================
// SEND RESET OTP
// ===============================

router.post("/forgot-password", async (req, res) => {

  try {

    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) return res.send("Email not registered");

    const otpCode = Math.floor(1000 + Math.random() * 9000).toString();

    await Otp.deleteMany({ email });

    const otpData = new Otp({
      email,
      otp: otpCode,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    await otpData.save();

    transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset OTP - Coastal Koffix",
      text: `Your password reset OTP is ${otpCode}`
    })
      .then(() => console.log("Reset OTP sent"))
      .catch(err => console.error("Reset Email Error:", err));

    res.redirect(`/reset-otp?email=${email}`);

  } catch (error) {
    console.error(error);
    res.send("Reset request failed");
  }

});

// ===============================
// RESET OTP PAGE
// ===============================

router.get("/reset-otp", (req, res) => {
  res.render("resetOtp", { email: req.query.email });
});

// ===============================
// VERIFY RESET OTP
// ===============================

router.post("/reset-otp", async (req, res) => {

  try {

    const { email, otp } = req.body;

    const record = await Otp.findOne({ email, otp });

    if (!record) return res.send("Invalid OTP");

    if (record.expiresAt < new Date()) return res.send("OTP expired");

    res.redirect(`/reset-password?email=${email}`);

  } catch (error) {
    console.error(error);
    res.send("OTP verification failed");
  }

});

// ===============================
// RESET PASSWORD PAGE
// ===============================

router.get("/reset-password", (req, res) => {
  res.render("resetPassword", { email: req.query.email });
});

// ===============================
// UPDATE PASSWORD
// ===============================

router.post("/reset-password", async (req, res) => {

  try {

    const { email, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
      return res.send("Passwords do not match");
    }

    const passwordRegex =
      /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{6,}$/;

    if (!passwordRegex.test(password)) {
      return res.send("Password rule not matched");
    }

    const hashedPassword = await argon2.hash(password);

    await User.updateOne(
      { email },
      { $set: { password: hashedPassword } }
    );

    await Otp.deleteMany({ email });

    res.redirect("/login");

  } catch (error) {
    console.error(error);
    res.send("Password reset failed");
  }

});

// ===============================
// LOGOUT
// ===============================

router.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

module.exports = router;
