const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const authRoutes = require('./Route/auth');
const productRoutes = require('./Route/productRoute');
const commentRoutes = require('./Route/commentRoute');
const userRoutes = require('./Route/userRoute');
const os = require('os');
require('./config/passport'); 
dotenv.config(); // Load environment variables from .env file
const app = express();

const connectToMongo = async () => {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to MongoDB");
};

connectToMongo();

app.use(cors())
app.use(cookieParser());
app.use(express.json());
// Lấy địa chỉ IP động
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
//ROUTES
app.use("/v1/auth", authRoutes);
app.use("/v1/products", productRoutes);
app.use("/v1/comments", commentRoutes);
app.use("/v1/users", userRoutes);
// app.listen(8000, () => {
//     console.log('Server is running on port http://localhost:8000');
// });
// app.listen(8000, '10.13.11.129', () => {
//     console.log('Server is running on http://10.13.11.129:8000');
// });
const ip = getLocalIp();
app.listen(8000, ip, () => {
    console.log(`Server is running on http://${ip}:8000`);
});
