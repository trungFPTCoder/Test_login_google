const middlewareController = require("../controllers/middlewareController");
const {
  createProduct,
  getProducts,
  getProductById,
  updateProduct,
  deleteProduct,
  likeProduct,
} = require("../controllers/productControllers");

const routes = require("express").Router();

// Create a new product
// POST http://10.13.11.129:8000/v1/products/create
routes.post("/create", middlewareController.verifyToken, createProduct);
// Get all products
// GET http://10.13.11.129:8000/v1/products
routes.get("/", getProducts);
// Get a single product by ID
// GET http://10.13.11.129:8000/v1/products/:id
routes.get("/:id", getProductById);
// Update a product by ID
// PUT http://10.13.11.129:8000/v1/products/:id
routes.put("/:id", middlewareController.verifyToken, updateProduct);
// Delete a product by ID
// DELETE http://10.13.11.129:8000/v1/products/:id
routes.delete("/:id", middlewareController.verifyToken, deleteProduct);

// Like a product
// POST http://10.13.11.129:8000/v1/products/:id/like
routes.post("/:id/like", middlewareController.verifyToken, likeProduct);

module.exports = routes;
