const Product = require("../models/Products");

// Create a new product
exports.createProduct = async (req, res) => {
  try {
    const { name, description, price, image } = req.body;
    const existingProduct = await Product.findOne({ name });
    if (existingProduct) {
      return res
        .status(400)
        .json({ error: "Product with this name already exists" });
    }
    const product = new Product({ name, description, price, image });
    await product.save();
    res.status(201).json({ message: "Product created successfully", product });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

// Get all products
exports.getProducts = async (req, res) => {
  try {
    const products = await Product.find();
    res
      .status(200)
      .json({ message: "Products retrieved successfully", products });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Get a single product by ID
exports.getProductById = async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: "Product not found" });
    res
      .status(200)
      .json({ message: "Product retrieved successfully", product });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Update a product by ID
exports.updateProduct = async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(req.params.id, req.body);
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.status(200).json({ message: "Product updated successfully"});
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

// Delete a product by ID
exports.deleteProduct = async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.status(200).json({ message: "Product deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.likeProduct = async (req, res) => {
  try {
    const userId = req.body.userId;
    const productId = req.params.id;
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ error: "Product not found" });
    if (product.likes.includes(userId)) {
      // User already liked the product, remove like (unlike)
      product.likes = product.likes.filter(id => id.toString() !== userId);
    } else {
      // User has not liked the product, add like
      product.likes.push(userId);
    }
    await product.save();
    res.status(200).json({ message: "Product liked successfully", product });
  } catch (error) {
    res.status(500).json({ error: error.message });   
  }
};