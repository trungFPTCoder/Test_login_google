const middlewareController = require("../controllers/middlewareController");
const {
  getComments,
  addComment,
} = require("../controllers/commentControllers");

const routes = require("express").Router();

// Get comments for a product
// GET http://10.13.11.129:8000/v1/comments/:productId
routes.get("/:productId", getComments);

// Add a comment
// POST http://10.13.11.129:8000/v1/comments
routes.post("/", middlewareController.verifyToken, addComment);

module.exports = routes;
