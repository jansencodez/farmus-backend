import connectDB from '../../config/db';
import authenticateToken from '../../utils/authenticateToken';
import User from '../../models/User';

export default async function handler(req, res) {
  await connectDB(); // Ensure the database is connected

  // Only handle GET requests
  if (req.method !== 'GET') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  // Authenticate the user
  return authenticateToken(req, res, async () => {
    try {
      // Find the user by the authenticated user's ID
      const user = await User.findById(req.user.userId);

      // If user is not found, return a 404 error
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Return the user's wallet balance
      res.status(200).json({ balance: user.walletBalance });
    } catch (error) {
      console.error('Error fetching balance:', error);
      res.status(500).json({ message: 'Failed to fetch balance', error });
    }
  });
}
