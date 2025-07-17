const express = require("express");
const router = express.Router();
const Comment = require("../models/Comment");


exports.getComments = async (req, res) => {
  try {
    const { productId } = req.params;
    const comments = await Comment.find({ productId }).populate("userId", "fullname").sort({ createdAt: -1 });
    res
      .status(200)
      .json({ message: "Comments retrieved successfully", comments });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
// Add a comment
exports.addComment = async (req, res) => {
  try {
    const { productId, userId, content } = req.body;
    const comment = new Comment({ productId, userId, content });
    await comment.save();
    res.status(201).json({ message: "Comment added successfully", comment });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

