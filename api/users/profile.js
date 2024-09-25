const User = require('../../models/User');
const authenticateToken = require('../../utils/authenticateToken');
const connectDB = require('../../config/db');

module.exports = async (req, res) => {
  await connectDB();

  // Run the authenticateToken middleware
  authenticateToken(req, res, async () => {
    try {
      const user = await User.findById(req.user.userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      res.json({
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          profilePicture: user.profilePicture,
        },
        products: user.products,
      });
    } catch (err) {
      res.status(500).json({ message: 'Server error' });
    }
  });
};
