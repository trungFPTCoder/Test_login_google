// ✅ BẮT BUỘC: Đặt dòng này lên đầu tiên để nạp biến môi trường
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const os = require('os');

// Import các routes
const authRoutes = require('./Route/auth');
const productRoutes = require('./Route/productRoute');
const commentRoutes = require('./Route/commentRoute');
const userRoutes = require('./Route/userRoute');

// Cấu hình Passport sẽ được nạp từ controller khi authRoutes được require,
// nên không cần require riêng ở đây nếu đã có trong controller.

const app = express();

// --- KẾT NỐI DATABASE ---
const connectToMongo = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log("✅ Connected to MongoDB");
    } catch (err) {
        console.error("❌ Could not connect to MongoDB", err);
        process.exit(1); // Thoát ứng dụng nếu không kết nối được DB
    }
};

connectToMongo();

// --- MIDDLEWARE ---
app.use(cors());
app.use(cookieParser());
app.use(express.json());
app.use(passport.initialize()); // Khởi tạo passport

// --- ROUTES ---
app.use("/v1/auth", authRoutes);
app.use("/v1/products", productRoutes);
app.use("/v1/comments", commentRoutes);
app.use("/v1/users", userRoutes);

// --- START SERVER ---
function getLocalIp() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return 'localhost';
}

const ip = getLocalIp();
const PORT = process.env.PORT || 8000;
app.listen(PORT, ip, () => {
    console.log(`🚀 Server is running on http://${ip}:${PORT}`);
});
