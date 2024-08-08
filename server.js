require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

var app = express();

app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  resetToken: String,
  resetTokenExpiry: Date,
});
const User = mongoose.model("User", userSchema);

// Endpoint to send a password recovery link
app.post("/Website/send_forgot_password_recovery_link", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ status: 404, msg: "User not found." });
    }

    // Generate a secure token
    const token = crypto.randomBytes(32).toString("hex");
    const expiry = Date.now() + 3600000; // 1 hour from now

    user.resetToken = token;
    user.resetTokenExpiry = expiry;
    await user.save();

    // Generate recovery link
    const recoveryLink = `${process.env.FRONTEND_URL}/reset_password?token=${token}&email=${email}`;

    // Configure nodemailer
    const transporter = nodemailer.createTransport({
      service: "gmail", // or your preferred email service
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Recovery",
      text: `Please use the following link to reset your password: ${recoveryLink}`,
    };

    await transporter.sendMail(mailOptions);

    res
      .status(200)
      .json({ status: 200, msg: "Recovery link sent successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 500, msg: "Internal server error." });
  }
});

// Endpoint to reset password
app.post("/Website/reset_password", async (req, res) => {
  const { token, email, newPassword } = req.body;

  try {
    const user = await User.findOne({
      email,
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }, // Token should not be expired
    });

    if (!user) {
      return res
        .status(400)
        .json({ status: 400, msg: "Invalid or expired token." });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.status(200).json({ status: 200, msg: "Password reset successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 500, msg: "Internal server error." });
  }
});


// Centralized error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ status: 500, msg: 'Something went wrong!' });
  });


// Start the server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
