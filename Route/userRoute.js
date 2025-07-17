const middlewareController = require("../controllers/middlewareController");
const {
  updateUserProfile,
  getLikedProductsByUser,
} = require("../controllers/userControllers");

const routes = require("express").Router();

// Update user profile
// PUT http://10.13.11.129:8000/v1/users/:userId
routes.put("/:userId", middlewareController.verifyToken, updateUserProfile);

// Get liked products by user
// GET http://10.13.11.129:8000/v1/users/:userId/liked-products
routes.get("/:userId/liked-products", middlewareController.verifyToken, getLikedProductsByUser);

module.exports = routes;
