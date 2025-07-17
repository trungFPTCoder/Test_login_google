const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    fullname: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
    },
    // ✅ THAY ĐỔI QUAN TRỌNG Ở ĐÂY
    password: {
        type: String,
        // Mật khẩu chỉ bắt buộc khi không có googleId
        required: function() { return !this.googleId; },
        minlength: 6,
    },
    admin: {
        type: Boolean,
        default: false,
    },
    avatar: {
        type: String,
        default: "https://i.pinimg.com/564x/a2/5a/68/a25a68b31a39bff5203b74a49629b3a0.jpg"
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    googleId: {
        type: String,
        unique: true,
        // 'sparse' cho phép nhiều document có giá trị null/undefined cho trường unique này
        sparse: true, 
    },
    // Bạn có thể thêm các trường khác nếu cần
    // likedProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],

}, { timestamps: true }); // timestamps sẽ tự động thêm createdAt và updatedAt

module.exports = mongoose.model('User', userSchema);
