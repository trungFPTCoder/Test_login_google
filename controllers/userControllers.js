const User = require("../models/User");
const Product = require("../models/Products");
exports.updateUserProfile = async (req, res) => {
  try {
    const { userId } = req.params;
    const { fullname, userImage } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { fullname, userImage },
      { new: true}
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }
    // Xóa trường password trước khi trả về
    const userObj = updatedUser.toObject();
    delete userObj.password;
    res.status(200).json({
      message: "User profile updated successfully",
      user: userObj,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.getLikedProductsByUser = async (req, res) => {
  try {
    const userId = req.params.userId;
    const products = await Product.find({ likes: userId });
    res.status(200).json({
      message: "Liked products retrieved successfully",
      products,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};