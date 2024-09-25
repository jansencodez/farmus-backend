const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const User = require('../models/User');
const Product = require('../models/Product'); // Import the Product model
const router = express.Router();
const mongoose = require('mongoose');
const fs = require('fs');
const crypto = require('crypto');
const sendMail = require('../config/mailer');


// Set up multer for file handling
const upload = multer({
  dest: 'uploads/', // Directory to save uploaded files
  limits: { fileSize: 10 * 1024 * 1024 }, // Limit file size to 10MB
  fileFilter(req, file, cb) {
    if (!file.originalname.match(/\.(jpg|jpeg|png)$/)) {
      return cb(new Error('Please upload an image'));
    }
    cb(null, true);
  }
});

// Middleware to authenticate user based on JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('No token provided');
    return res.sendStatus(401); // Unauthorized if no token is provided
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token verification failed:', err.message);
      return res.sendStatus(403); // Forbidden if token is invalid
    }
    req.user = { userId: user.userId }; // Ensure the userId is set correctly
    next();
  });
};

router.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token required' });
  }

  try {
    // Verify the refresh token
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    
    // Find user based on the payload
    const user = await User.findById(payload.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Generate new tokens
    const newToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const newRefreshToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    // Send new tokens to client
    res.json({ newToken, newRefreshToken });

  } catch (error) {
    console.error('Error refreshing token:', error.message);
    res.status(401).json({ message: 'Invalid refresh token' });
  }
});


// Sign-Up Route
router.post('/signup', upload.single('profilePicture'), async (req, res) => {
  const { name, email, password } = req.body;

  // Handle uploaded file
  const profilePicture = req.file ? req.file.path : null;

  try {
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Create a new user
    user = new User({ name, email, password, profilePicture });
    await user.save();

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '30m' });

    res.status(201).json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Sign-In Route
router.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    let user = await User.findOne({ email });
    if (!user) {
      console.log('User does not exist');
      return res.status(400).json({ message: 'User does not exist' });
    }

    // Check password using bcrypt.compare
    const isMatch = await bcrypt.compare(password, user.password);
    console.log('Password Match:', isMatch); // Log result of comparison

    if (!isMatch) {
      console.log('Invalid credentials');
      return res.status(400).json({ message: 'Invalid password' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Optionally log the token for debugging (remove in production)
    console.log('Generated Token:', token);

    // Respond with token and user information
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      }
    });
  } catch (err) {
    console.error('Signin Error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

 // Use environment variable

router.post('/reset-password', async (req, res) => {
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
});





// routes/auth.js
router.post('/reset-password/confirm', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
    }

    // Update user password
    user.password = newPassword; // Make sure to hash the password before saving
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password has been reset successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Profile Route
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    // Find the user by ID from the JWT token
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Return user data and products
    res.json({
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        profilePicture: user.profilePicture,
      },
      products: user.products // Assuming you have products associated with the user
    });
  } catch (err) {
    console.error('Profile Fetch Error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get User Details by ID Route
router.get('/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create a new product listing
router.post('/create-listing', authenticateToken, upload.single('productImage'), async (req, res) => {
  const { name, description, price, category } = req.body;
  const productImage = req.file ? req.file.path : null;

  try {
    // Ensure that req.user.userId exists
    if (!req.user || !req.user.userId) {
      return res.status(400).json({ message: 'User ID is required to create a product listing.' });
    }

    // Convert price from string to Decimal128
    const formattedPrice = price ? mongoose.Types.Decimal128.fromString(price) : null;

    // Create a new product listing
    const product = new Product({
      name,
      description,
      price: formattedPrice,
      imageUrl: productImage,
      category,
      createdBy: req.user.userId // Associate product with the authenticated user
    });

    await product.save();

    // Optionally, update user's product list
    await User.findByIdAndUpdate(req.user.userId, { $push: { products: product._id } });

    res.status(201).json({ message: 'Product listing created successfully', product });
  } catch (err) {
    console.error('Create Listing Error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});
// Update user profile
router.put('/update', authenticateToken, upload.single('profilePicture'), async (req, res) => {
  try {
    // Extract user ID from the authenticated user
    const userId = req.user.userId;

    // Extract updated profile data from the request body
    const { name, email } = req.body;

    // Handle uploaded file
    const profilePicture = req.file ? req.file.path : null;

    // Validate the request body
    if (!name || !email) {
      return res.status(400).json({ message: 'Name and email are required' });
    }

    // Update the user in the database
    const updateData = { name, email };
    if (profilePicture) {
      updateData.profilePicture = profilePicture;
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true } // Return the updated user
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Return the updated user
    res.json({ user: updatedUser });
  } catch (error) {
    console.error('Error updating profile:', error); // Log error for debugging
    res.status(500).json({ message: 'Server error' });
  }
});

router.get('/products/:id', async (req, res) => {
  try {
    // Validate ObjectId
    const productId = req.params.id;
    if (!mongoose.Types.ObjectId.isValid(productId)) {
      return res.status(400).json({ message: 'Invalid product ID format' });
    }

    // Find the product by ID
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Return the product
    res.json(product);
  } catch (error) {
    console.error('Error fetching product:', error); // Log error for debuggings
    res.status(500).json({ message: 'Server error' });
  }
});
// Get All Products Route
router.get('/products', async (req, res) => {
  try {
    const products = await Product.find();

    // Transform products to remove MongoDB-specific types
    const transformedProducts = products.map(product => ({
      ...product.toObject(),
      price: product.price.toString() // Convert Decimal128 to string
    }));

    res.json(transformedProducts);
  } catch (err) {
    console.error('Error fetching products:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

router.delete('/products/:id', authenticateToken, async (req, res) => {
  try {
    const productId = req.params.id;

    // Find the product by ID
    const product = await Product.findById(productId);

    // Ensure the product exists
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Ensure the user is authorized to delete the product
    if (product.createdBy.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'You are not authorized to delete this product' });
    }

    // Delete the image file if it exists
    if (product.imageUrl) {
      fs.unlink(product.imageUrl, (err) => {
        if (err) {
          console.error('Error deleting product image:', err);
        } else {
          console.log('Product image deleted successfully');
        }
      });
    }

    // Delete the product
    await Product.findByIdAndDelete(productId);

    // Optionally, remove the product from the user's product list
    await User.findByIdAndUpdate(req.user.userId, { $pull: { products: productId } });

    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    console.error('Error deleting product:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


//wallet

// GET /api/wallet/details
router.get('/balance', authenticateToken, async (req, res) => {
  try {
      const user = await User.findById(req.user.userId);

      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      res.status(200).json({ balance: user.walletBalance });
  } catch (error) {
      console.error('Error fetching balance:', error);
      res.status(500).json({ message: 'Failed to fetch balance', error });
  }
});




// POST /deposit-funds
router.post('/deposit-funds', authenticateToken, async (req, res) => {
  const { amount } = req.body;

  if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Valid amount is required' });
  }

  try {
      const user = await User.findById(req.user.userId);

      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      // Implement M-Pesa deposit functionality
      const mpesaResponse = await initiateMpesaDeposit(amount, user.phoneNumber);

      if (mpesaResponse.ResponseCode === '0') {
          user.walletBalance = (parseFloat(user.walletBalance) + parseFloat(amount)).toFixed(2);
          await user.save();
          res.status(200).json({ message: 'Funds deposited successfully', balance: user.walletBalance });
      } else {
          res.status(500).json({ message: 'Failed to initiate deposit', mpesaResponse });
      }
  } catch (error) {
      console.error('Error depositing funds:', error);
      res.status(500).json({ message: 'Failed to deposit funds', error });
  }
});



// POST /api/wallet/withdraw-funds
router.post('/withdraw-funds', authenticateToken, async (req, res) => {
  const { amount, phoneNumber } = req.body;

  if (!amount || amount <= 0 || !phoneNumber) {
      return res.status(400).json({ message: 'Amount and phone number are required' });
  }

  try {
      const user = await User.findById(req.user.userId);

      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      if (user.walletBalance < amount) {
          return res.status(400).json({ message: 'Insufficient balance' });
      }

      user.walletBalance = (parseFloat(user.walletBalance) - parseFloat(amount)).toFixed(2);
      await user.save();

      const transactionId = user._id.toString();
      const mpesaResponse = await initiateMpesaWithdrawal(amount, phoneNumber, transactionId);

      if (mpesaResponse.ResponseCode === '0') {
          res.status(200).json({ message: 'Withdrawal initiated successfully', mpesaResponse });
      } else {
          user.walletBalance = (parseFloat(user.walletBalance) + parseFloat(amount)).toFixed(2);
          await user.save();
          res.status(500).json({ message: 'Failed to initiate withdrawal', mpesaResponse });
      }
  } catch (error) {
      console.error('Error withdrawing funds:', error);
      res.status(500).json({ message: 'Failed to withdraw funds', error });
  }
});



router.post('/purchase-item', authenticateToken, async (req, res) => {
  const { itemId, amount, sellerId } = req.body;

  if (!itemId || !amount || !sellerId) {
      return res.status(400).json({ message: 'Item ID, amount, and seller ID are required' });
  }

  try {
      const buyer = await User.findById(req.user.userId);
      const seller = await User.findById(sellerId);

      if (!buyer || !seller) {
          return res.status(404).json({ message: 'User not found' });
      }

      if (buyer.walletBalance < amount) {
          return res.status(400).json({ message: 'Insufficient balance' });
      }

      buyer.walletBalance = (parseFloat(buyer.walletBalance) - parseFloat(amount)).toFixed(2);
      await buyer.save();

      seller.walletBalance = (parseFloat(seller.walletBalance) + parseFloat(amount)).toFixed(2);
      await seller.save();

      res.status(200).json({ message: 'Purchase successful', buyerBalance: buyer.walletBalance, sellerBalance: seller.walletBalance });
  } catch (error) {
      console.error('Error processing purchase:', error);
      res.status(500).json({ message: 'Failed to process purchase', error });
  }
});


module.exports = router;
