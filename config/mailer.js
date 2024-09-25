const nodemailer = require('nodemailer');
require('dotenv').config(); // Load environment variables

// Create a Nodemailer transporter using environment variables for sensitive info
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // Your email address stored in .env
    pass: process.env.EMAIL_PASS, // Your email password stored in .env
  },
});

// Function to send an email
const sendMail = (to, subject, text) => {
  const mailOptions = {
    from: process.env.EMAIL_USER, // Sender email from env variables
    to,
    subject,
    text,
  };

  return transporter.sendMail(mailOptions);
};

module.exports = sendMail;
