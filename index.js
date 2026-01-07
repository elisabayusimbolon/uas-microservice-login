const express = require('express');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// ENVIRONMENT VARIABLES
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = 'kependudukan_db';
const SECRET_KEY = process.env.SECRET_KEY || 'rahasia_negara_top_secret'; // Kunci JWT

if (!MONGODB_URI) console.error("⚠️ MONGODB_URI belum di-set!");

app.get('/', (req, res) => res.send('Microservice Login: ONLINE'));

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email dan Password wajib diisi!" });
    }

    let client;
    try {
        client = new MongoClient(MONGODB_URI);
        await client.connect();
        const db = client.db(DB_NAME);
        const users = db.collection('users');

        // 1. Cari User berdasarkan Email
        const user = await users.findOne({ email: email });

        // Jika user tidak ditemukan
        if (!user) {
            return res.status(401).json({ error: "Email tidak terdaftar!" });
        }

        // 2. Cek Password (Bandingkan Input vs Hash Database)
        // Ini bagian penting yang sebelumnya mungkin belum ada
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Password salah!" });
        }

        // 3. Login Sukses -> Buat Token KTP Digital (JWT)
        const token = jwt.sign(
            { 
                id: user._id, 
                email: user.email, 
                nama: user.nama 
            }, 
            SECRET_KEY, 
            { expiresIn: '1h' } // Token berlaku 1 jam
        );

        res.json({ 
            message: "Login Berhasil!", 
            token: token 
        });

    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: "Terjadi kesalahan server login" });
    } finally {
        if (client) client.close();
    }
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`Server Login jalan di port ${PORT}`));

module.exports = app;