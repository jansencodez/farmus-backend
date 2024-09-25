const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const connectDB = require('./config/db');
const authRoutes = require("./routes/auth");
dotenv.config();
connectDB();

const app = express();

app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/uploads', express.static('uploads'));
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
