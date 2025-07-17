const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    fullname: {
        type: String,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    userImage: {
        type: String,
        default: 'default_user.png',
    },
    admin: {
        type: Boolean,
        default: false,
    },
}, { timestamps: true, collection: 'users' });

module.exports = mongoose.model('User', userSchema);