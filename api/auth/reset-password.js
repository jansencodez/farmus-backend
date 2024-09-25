const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../../models/User');
const connectDB = require('../../config/db');


export default async function handler(req, res){
  await connectDB();
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Generate a reset token
    const token = crypto.randomBytes(12).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

    // Save the updated user with the reset token and expiry
    await user.save();

    // Send reset email
    const resetLink = `${baseUrl}/reset-password/confirm?token=${token}`;
    const subject = 'Password Reset Request';
    const text = `You requested a password reset. Click the link below to reset your password:\n\n${resetLink}\n\nIf you did not request this, please ignore this email.`;

    await sendMail(email, subject, text);

    res.status(200).json({ message: 'Password reset email sent.' });
  } catch (error) {
    console.error(error); // Log the actual error
    res.status(500).json({ message: 'Server error' });
  }
}