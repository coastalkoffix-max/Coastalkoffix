const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({

  firstName: String,
  middleName: String,
  lastName: String,

  mobile: String,

  country: String,
  state: String,
  district: String,
  pinCode: String,

  email: {
    type: String,
    unique: true
  },

  password: String,

  isVerified: {
    type: Boolean,
    default: false
  },

  createdAt: {
    type: Date,
    default: Date.now
  }

});

module.exports = mongoose.model("User", userSchema);
