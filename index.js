// FILE: uas-microservice-login/index.js
// FUNCTION: AUTH SERVICE (Register + Login)

const express = require('express');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// --- KONFIGURASI DATABASE KHUSUS AUTH ---
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = 'microservice_auth'; // Database 1
const SECRET_KEY = process.env.SECRET_KEY || 'kunci_rahasia_negara';

if (!MONGODB_URI) console.error("⚠️ MONGODB_URI belum di-set di Vercel!");

// --- 1. REGISTER USER BARU ---
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email & Password wajib diisi!" });

    let client = new MongoClient(MONGODB_URI);
    try {
        await client.connect();
        const db = client.db(DB_NAME);
        
        // Cek apakah email sudah ada
        const exist = await db.collection('users').findOne({ email });
        if (exist) return res.status(400).json({ error: "Email ini sudah terdaftar!" });

        // Enkripsi Password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Simpan ke Database
        await db.collection('users').insertOne({
            email,
            password: hashedPassword,
            createdAt: new Date()
        });

        res.status(201).json({ message: "Registrasi Berhasil! Silakan Login." });
    } catch (e) {
        res.status(500).json({ error: "Server Error: " + e.message });
    } finally {
        client.close();
    }
});

// --- 2. LOGIN USER ---
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    let client = new MongoClient(MONGODB_URI);
    try {
        await client.connect();
        const db = client.db(DB_NAME);

        // Cari user
        const user = await db.collection('users').findOne({ email });
        if (!user) return res.status(401).json({ error: "Email tidak ditemukan!" });

        // Cek password
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(401).json({ error: "Password salah!" });

        // Buat Token (KTP Sementara)
        const token = jwt.sign({ id: user._id, email: user.email }, SECRET_KEY, { expiresIn: '2h' });
        
        res.json({ message: "Login Sukses", token });
    } catch (e) {
        res.status(500).json({ error: "Server Error" });
    } finally {
        client.close();
    }
});

// Default Route
app.get('/', (req, res) => res.send("AUTH SERVICE IS RUNNING..."));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth Service running on port ${PORT}`));
module.exports = app;