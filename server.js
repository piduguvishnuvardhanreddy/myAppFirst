// server.js
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cron = require('node-cron');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/protectedRoutes');


dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


