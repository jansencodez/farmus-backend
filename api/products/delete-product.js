import connectDB from '../../config/db';
import Product from '../../models/Product';
import authenticateToken from '../../utils/authenticateToken';

export default async function handler(req, res) {
  // Ensure database connection
  await connectDB();

  // Only allow DELETE method
  if (req.method !== 'DELETE') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  // Authenticate the user using the token
  return authenticateToken(req, res, async () => {
    const { id } = req.query; // Extract product ID from query params

    try {
      // Find the product by ID
      const product = await Product.findById(id);
      if (!product) {
        return res.status(404).json({ message: 'Product not found' });
      }

      // Check if the authenticated user is the creator of the product
      if (product.createdBy.toString() !== req.user.userId) {
        return res.status(403).json({ message: 'Unauthorized' });
      }

      // Delete the product
      await Product.findByIdAndDelete(id);
      res.json({ message: 'Product deleted successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Server error' });
    }
  });
}
