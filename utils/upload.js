// utils/upload.js
const multer = require('multer');
const path = require('path');

const upload = multer({
  dest: '/tmp/', // Vercel Serverless Functions use `/tmp` directory for file uploads
  limits: { fileSize: 5 * 1024 * 1024 }, // 10MB limit
  fileFilter(req, file, cb) {
    if (!file.originalname.match(/\.(jpg|jpeg|png)$/)) {
      return cb(new Error('Please upload an image'));
    }
    cb(null, true);
  }
});

module.exports = upload;
