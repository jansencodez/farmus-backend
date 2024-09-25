import connectDB from '../../config/db';
import Product from '../../models/Product';

export default async function handler(req, res) {
  await connectDB();

  if (req.method !== 'GET') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  try {
    const products = await Product.find();
    // Transform products to remove MongoDB-specific types
    const transformedProducts = products.map(product => ({
      ...product.toObject(),
      price: product.price.toString() // Convert Decimal128 to string 
    }));

    res.json(transformedProducts);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
}
