const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: String,
  _id: String,
  email: String,
  password: String,
  admin: Boolean,
});

const User = mongoose.model("User", userSchema);

module.exports = User;