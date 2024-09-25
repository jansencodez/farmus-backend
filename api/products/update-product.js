import connectDB from '../../utils/dbConnect';
import Product from '../../models/Product';
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  await connectDB();

  const { id } = req.query;

  if (req.method !== 'PUT') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  try {
    const token = req.headers['authorization']?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    if (product.createdBy.toString() !== decoded.userId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const updatedProduct = await Product.findByIdAndUpdate(id, req.body, { new: true });
    res.json(updatedProduct);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
}
