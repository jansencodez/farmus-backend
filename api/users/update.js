const User = require('../../models/User');
const authenticateToken = require('../../utils/authenticateToken');
const upload = require('../../utils/upload');
const connectDB = require('../../config/db');

module.exports = async (req, res) => {
  await connectDB();

  // Authenticate the user using the token
  authenticateToken(req, res, async () => {
    // Use the upload middleware for handling profile picture uploads
    upload.single('profilePicture')(req, res, async (err) => {
      if (err) {
        return res.status(400).json({ message: 'File upload error' });
      }

      try {
        // Extract user ID from the authenticated user
        const userId = req.user.userId;

        // Extract updated profile data from the request body
        const { name, email } = req.body;

        // Handle uploaded file for profile picture
        const profilePicture = req.file ? req.file.path : null;

        // Validate the request body
        if (!name || !email) {
          return res.status(400).json({ message: 'Name and email are required' });
        }

        // Prepare update data object
        const updateData = { name, email };
        if (profilePicture) {
          updateData.profilePicture = profilePicture; // Only update profile picture if uploaded
        }

        // Update the user in the database
        const updatedUser = await User.findByIdAndUpdate(
          userId,
          updateData,
          { new: true } // Return the updated user object
        );

        // If user not found
        if (!updatedUser) {
          return res.status(404).json({ message: 'User not found' });
        }

        // Return the updated user in the response
        res.json({ user: updatedUser });
      } catch (error) {
        console.error('Error updating profile:', error); // Log error for debugging
        res.status(500).json({ message: 'Server error' });
      }
    });
  });
};
