const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // Ini library buat bikin Token
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// --- KONEKSI DATABASE ---
// Kita akan pakai database yang SAMA dengan Register
const connectDB = async () => {
    if (mongoose.connections[0].readyState) return;
    // Nanti link-nya kita ambil dari Vercel
    await mongoose.connect(process.env.MONGODB_URI);
};

// --- MODEL USER ---
// Struktur harus sama persis dengan Register
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- ENDPOINT LOGIN ---
app.post('/api/login', async (req, res) => {
    try {
        await connectDB();
        const { email, password } = req.body;

        // 1. Cek User
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "Email tidak ditemukan" });

        // 2. Cek Password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Password salah" });

        // 3. Buat Token (Karcis Masuk)
        const token = jwt.sign(
            { id: user._id, email: user.email }, 
            process.env.JWT_SECRET, // Kunci rahasia stempel
            { expiresIn: '1h' }
        );

        res.json({ message: "Login Berhasil!", token });

    } catch (err) {
        res.status(500).json({ error: "Server Error" });
    }
});

app.get('/', (req, res) => res.send('Service Login Ready'));

module.exports = app;

// Kode agar bisa jalan di local & Vercel
if (require.main === module) {
    app.listen(3001, () => console.log('Login running on 3001'));
}