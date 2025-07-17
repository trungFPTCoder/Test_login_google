const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    description: {
        type: String,
        required: true,
    },
    price: {
        type: Number,
        required: true,
    },
    image: {
        type: String,
        default: "images/404-landing-page-free-vector.jpg",
    },
    likes: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: [],
    }],
}, { timestamps: true, collection: 'products' });

module.exports = mongoose.model('Product', productSchema);