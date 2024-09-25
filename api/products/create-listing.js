const mongoose = require('mongoose');
const Product = require('../../models/Product');
const User = require('../../models/User');
const authenticateToken = require('../../utils/authenticateToken');
const upload = require('../../utils/upload'); 
const connectDB = require('../../config/db');

export default async function handler(req, res) {
  await connectDB();

  // First authenticate the user
  authenticateToken(req, res, async () => {
    // Apply the upload middleware to handle file uploads
    upload.single('productImage')(req, res, async (err) => {
      if (err) {
        return res.status(400).json({ message: 'File upload error' });
      }

      const { name, description, price, category } = req.body;
      const productImage = req.file ? req.file.path : null; // Get the uploaded image file

      try {
        // Convert price to Decimal128 if provided
        const formattedPrice = price ? mongoose.Types.Decimal128.fromString(price) : null;

        // Create a new product
        const product = new Product({
          name,
          description,
          price: formattedPrice,
          imageUrl: productImage,
          category,
          createdBy: req.user.userId, // User's ID from the token
        });

        // Save the product to the database
        await product.save();

        // Associate the product with the user
        await User.findByIdAndUpdate(req.user.userId, { $push: { products: product._id } });

        // Send a success response
        res.status(201).json({ message: 'Product created successfully', product });
      } catch (err) {
        // Handle any errors
        res.status(500).json({ message: 'Server error' });
      }
    });
  });
};
