const express = require("express");
const argon2 = require("argon2");
const nodemailer = require("nodemailer");


const User = require("../models/User");
const Otp = require("../models/Otp");

const router = express.Router();


// ===============================
// EMAIL CONFIG
// ===============================

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});


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

  // SAVE USER TEMP (UNVERIFIED)
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

  // SAVE OTP
  const otpData = new Otp({
    email,
    otp: otpCode,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000)
  });

  await otpData.save();

  // SEND EMAIL
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Coastal Koffix OTP Verification",
    text: `Your OTP is ${otpCode}`
  });

  res.redirect(`/verify-otp?email=${email}`);

});


// ===============================
// OTP PAGE
// ===============================

router.get("/verify-otp", (req, res) => {

  const { email } = req.query;

  res.render("verifyOtp", { email });

});


// ===============================
// OTP VERIFY
// ===============================

router.post("/verify-otp", async (req, res) => {

  const { email, otp } = req.body;

  const otpRecord = await Otp.findOne({ email, otp });

  if (!otpRecord) {
    return res.send("Invalid OTP");
  }

  if (otpRecord.expiresAt < new Date()) {
    return res.send("OTP Expired");
  }

  // VERIFY USER
  await User.updateOne(
    { email },
    { $set: { isVerified: true } }
  );

  // DELETE OTP
  await Otp.deleteMany({ email });

  // CREATE SESSION
  const user = await User.findOne({ email });
  req.session.userId = user._id;

  res.redirect("/home");

});
router.get("/login", (req, res) => {
  res.render("login");
});

router.post("/login", async (req, res) => {

  const { email, password } = req.body;

  // Find user
  const user = await User.findOne({ email });

  if (!user) {
    return res.send("User not found");
  }

  // Check email verified
  if (!user.isVerified) {
    return res.send("Please verify OTP before login");
  }

  // Verify password
  const isPasswordMatch = await argon2.verify(
    user.password,
    password
  );

  if (!isPasswordMatch) {
    return res.send("Incorrect password");
  }

  // Create session
  req.session.userId = user._id;

  res.redirect("/home");

});
// ================================
// FORGOT PASSWORD PAGE
// ================================

router.get("/forgot-password", (req, res) => {
  res.render("forgotPassword");
});


// ================================
// SEND OTP FOR RESET
// ================================

router.post("/forgot-password", async (req, res) => {

  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return res.send("Email not registered");
  }

  const otpCode = Math.floor(1000 + Math.random() * 9000).toString();

  await Otp.deleteMany({ email });

  const otpData = new Otp({
    email,
    otp: otpCode,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000)
  });

  await otpData.save();

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Password Reset OTP - Coastal Koffix",
    text: `Your password reset OTP is ${otpCode}`
  });

  res.redirect(`/reset-otp?email=${email}`);

});


// ================================
// RESET OTP PAGE
// ================================

router.get("/reset-otp", (req, res) => {

  const { email } = req.query;

  res.render("resetOtp", { email });

});


// ================================
// VERIFY RESET OTP
// ================================

router.post("/reset-otp", async (req, res) => {

  const { email, otp } = req.body;

  const record = await Otp.findOne({ email, otp });

  if (!record) {
    return res.send("Invalid OTP");
  }

  if (record.expiresAt < new Date()) {
    return res.send("OTP Expired");
  }

  res.redirect(`/reset-password?email=${email}`);

});


// ================================
// RESET PASSWORD PAGE
// ================================

router.get("/reset-password", (req, res) => {

  const { email } = req.query;

  res.render("resetPassword", { email });

});


// ================================
// UPDATE PASSWORD
// ================================

router.post("/reset-password", async (req, res) => {

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

});
router.get("/logout", (req, res) => {

  req.session.destroy(() => {
    res.redirect("/login");
  });

});


module.exports = router;
