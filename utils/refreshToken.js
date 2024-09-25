const jwt = require('jsonwebtoken');


export default async function handler (req, res) {
  
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
}