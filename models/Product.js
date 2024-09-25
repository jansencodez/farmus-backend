const mongoose = require('mongoose');

const ProductSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
    },
    description: {
        type: String,
        trim: true,
    },
    price: {
        type: mongoose.Schema.Types.Decimal128,
        required: true,
        validate: {
            validator: function (value) {
                return value >= 0; // Price must be non-negative
            },
            message: 'Price must be a non-negative number',
        },
    },
    imageUrl: {
        type: String,
        trim: true,
    },
    category: {
        type: String,
        required: true,
        trim: true,
        enum: ['Vegetables', 'Fruits', 'Grains', 'Dairy', 'Meat', 'Others'], // Example categories
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
}, {
    timestamps: true, // Automatically adds createdAt and updatedAt fields
});

const Product = mongoose.model('Product', ProductSchema);
module.exports = Product;
