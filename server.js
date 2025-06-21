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


dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// MODELS
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['user', 'doctor', 'admin'], default: 'user' },
  resetToken: String,
  resetTokenExpiry: Date,
});
const User = mongoose.model('User', userSchema);

const doctorSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  department: String,
  resetToken: String,
  resetTokenExpiry: Date,
  weeklyAvailability: Object,
});
const Doctor = mongoose.model('Doctor', doctorSchema);

const slotSchema = new mongoose.Schema({
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
  date: String,
  slots: [
    {
      time: String,
      isBooked: { type: Boolean, default: false },
      heldUntil: Date
    }
  ]
});
const Slot = mongoose.model('Slot', slotSchema);

const appointmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
  date: String,
  time: String,
  status: { type: String, enum: ['booked', 'cancelled'], default: 'booked' }
});
const Appointment = mongoose.model('Appointment', appointmentSchema);

const feedbackSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
  rating: Number,
  comment: String,
  date: { type: Date, default: Date.now }
});
const Feedback = mongoose.model('Feedback', feedbackSchema);

const notificationSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  message: String,
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const Notification = mongoose.model('Notification', notificationSchema);

const blacklist = new Set();

// EMAIL UTILS
const sendEmail = async (to, subject, html) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
  await transporter.sendMail({ from: process.env.EMAIL_USER, to, subject, html });
};

// AUTH MIDDLEWARE
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token || blacklist.has(token)) return res.status(401).json({ error: 'Invalid token' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
};
const requireRole = (role) => (req, res, next) => {
  if (req.user.role !== role) return res.status(403).json({ error: 'Access denied' });
  next();
};

// PASSWORD RESET
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email }) || await Doctor.findOne({ email });
  if (!user) return res.status(404).json({ error: 'User not found' });
  const token = crypto.randomBytes(32).toString('hex');
  user.resetToken = token;
  user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
  await user.save();
  await sendEmail(user.email, 'Reset Password', `Reset here: ${process.env.CLIENT_URL}/reset-password/${token}`);
  res.json({ message: 'Reset email sent' });
});

app.post('/api/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } }) ||
               await Doctor.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
  if (!user) return res.status(400).json({ error: 'Invalid or expired token' });
  user.password = await bcrypt.hash(newPassword, 10);
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;
  await user.save();
  res.json({ message: 'Password reset successful' });
});

// DOCTOR PROFILE
app.put('/api/doctor/:id', verifyToken, requireRole('doctor'), async (req, res) => {
  const updated = await Doctor.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(updated);
});

// DEPARTMENTS
const departments = ['Cardiology', 'Neurology', 'Orthopedics', 'Pediatrics'];
app.get('/api/departments', (req, res) => {
  res.json(departments);
});

app.get('/api/doctors/department/:name', async (req, res) => {
  const doctors = await Doctor.find({ department: req.params.name });
  res.json(doctors);
});

app.get('/api/doctor/:id', async (req, res) => {
  const doctor = await Doctor.findById(req.params.id);
  res.json(doctor);
});

app.get('/api/slots/:doctorId/:date', async (req, res) => {
  const slots = await Slot.findOne({ doctorId: req.params.doctorId, date: req.params.date });
  res.json(slots);
});

app.post('/api/appointments', verifyToken, async (req, res) => {
  const { doctorId, date, time } = req.body;
  const slotDoc = await Slot.findOne({ doctorId, date });
  const slot = slotDoc?.slots.find(s => s.time === time);
  if (!slot || slot.isBooked) return res.status(409).json({ error: 'Slot not available' });
  slot.isBooked = true;
  await slotDoc.save();

  const appointment = new Appointment({ userId: req.user.id, doctorId, date, time });
  await appointment.save();
  res.json({ message: 'Appointment booked', appointment });
});

app.delete('/api/appointments/:id', verifyToken, async (req, res) => {
  const appnt = await Appointment.findById(req.params.id);
  if (!appnt) return res.status(404).json({ error: 'Appointment not found' });
  appnt.status = 'cancelled';
  await appnt.save();
  const slotDoc = await Slot.findOne({ doctorId: appnt.doctorId, date: appnt.date });
  const slot = slotDoc?.slots.find(s => s.time === appnt.time);
  if (slot) slot.isBooked = false;
  await slotDoc.save();
  res.json({ message: 'Appointment cancelled' });
});

app.get('/api/user/appointments', verifyToken, requireRole('user'), async (req, res) => {
  const appointments = await Appointment.find({ userId: req.user.id });
  res.json(appointments);
});

app.get('/api/doctor/appointments', verifyToken, requireRole('doctor'), async (req, res) => {
  const appointments = await Appointment.find({ doctorId: req.user.id });
  res.json(appointments);
});

// User Registration
app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  const existing = await User.findOne({ email }) || await Doctor.findOne({ email });
  if (existing) return res.status(400).json({ error: 'Email already exists' });

  const hashed = await bcrypt.hash(password, 10);
  let user;
  if (role === 'doctor') {
    user = new Doctor({ name, email, password: hashed });
  } else {
    user = new User({ name, email, password: hashed, role });
  }

  await user.save();
  res.json({ message: 'Registration successful' });
});

// User Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email }) || await Doctor.findOne({ email });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.json({ token, user: { id: user._id, name: user.name, role: user.role } });
});

// Get all users or doctors (admin only)
app.get('/api/admin/users', verifyToken, requireRole('admin'), async (req, res) => {
  const users = await User.find();
  const doctors = await Doctor.find();
  res.json({ users, doctors });
});

// Promote user to doctor or admin
app.put('/api/admin/promote/:id', verifyToken, requireRole('admin'), async (req, res) => {
  const { role } = req.body;
  const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// Submit feedback
app.post('/api/feedback', verifyToken, requireRole('user'), async (req, res) => {
  const { doctorId, rating, comment } = req.body;
  const feedback = new Feedback({ userId: req.user.id, doctorId, rating, comment });
  await feedback.save();
  res.json({ message: 'Feedback submitted' });
});

// Get feedback for doctor
app.get('/api/feedback/:doctorId', async (req, res) => {
  const feedbacks = await Feedback.find({ doctorId: req.params.doctorId });
  res.json(feedbacks);
});

// Get notifications
app.get('/api/notifications', verifyToken, async (req, res) => {
  const notes = await Notification.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(notes);
});

// Mark notification as read
app.put('/api/notifications/:id/read', verifyToken, async (req, res) => {
  await Notification.findByIdAndUpdate(req.params.id, { read: true });
  res.json({ message: 'Notification marked as read' });
});

app.put('/api/doctor/:id/availability', verifyToken, requireRole('doctor'), async (req, res) => {
  const { weeklyAvailability } = req.body;
  const updated = await Doctor.findByIdAndUpdate(req.params.id, { weeklyAvailability }, { new: true });
  res.json(updated);
});

app.put('/api/user/:id', verifyToken, async (req, res) => {
  if (req.user.id !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
  const updated = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(updated);
});

app.post('/api/logout', verifyToken, (req, res) => {
  blacklist.add(req.headers['authorization']);
  res.json({ message: 'Logged out' });
});

// Hold a slot for 2 minutes
app.post('/api/slots/hold', verifyToken, async (req, res) => {
  const { doctorId, date, time } = req.body;
  const slotDoc = await Slot.findOne({ doctorId, date });
  const slot = slotDoc?.slots.find(s => s.time === time);

  if (!slot || slot.isBooked || (slot.heldUntil && slot.heldUntil > Date.now())) {
    return res.status(409).json({ error: 'Slot unavailable or held' });
  }

  slot.heldUntil = new Date(Date.now() + 2 * 60 * 1000); // hold for 2 minutes
  await slotDoc.save();
  res.json({ message: 'Slot held', heldUntil: slot.heldUntil });
});

cron.schedule('0 * * * *', async () => {
  const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const dateStr = tomorrow.toISOString().slice(0, 10);
  const appointments = await Appointment.find({ date: dateStr });

  for (const appnt of appointments) {
    const user = await User.findById(appnt.userId);
    const doctor = await Doctor.findById(appnt.doctorId);
    await sendEmail(user.email, 'Appointment Reminder',
      `Reminder: You have an appointment with Dr. ${doctor.name} at ${appnt.time} on ${dateStr}`);
  }
});

app.get('/api/doctor/:id', async (req, res) => {
  const doctor = await Doctor.findById(req.params.id);
  const feedbacks = await Feedback.find({ doctorId: doctor._id });

  const avgRating = feedbacks.length
    ? feedbacks.reduce((acc, f) => acc + f.rating, 0) / feedbacks.length
    : null;

  res.json({ doctor, avgRating, feedbacks });
});

app.get('/api/admin/dashboard', verifyToken, requireRole('admin'), async (req, res) => {
  const users = await User.countDocuments();
  const doctors = await Doctor.countDocuments();
  const appointments = await Appointment.countDocuments({ status: 'booked' });
  const feedbacks = await Feedback.find();

  const avgRating = feedbacks.length
    ? feedbacks.reduce((sum, fb) => sum + fb.rating, 0) / feedbacks.length
    : 0;

  res.json({ users, doctors, appointments, avgRating });
});

app.get('/api/doctors/search', async (req, res) => {
  const { q } = req.query;
  const doctors = await Doctor.find({
    $or: [
      { name: new RegExp(q, 'i') },
      { department: new RegExp(q, 'i') }
    ]
  });
  res.json(doctors);
});

const generateSlots = async () => {
  const doctors = await Doctor.find();

  for (const doc of doctors) {
    const availability = doc.weeklyAvailability;
    const today = new Date();

    for (let i = 0; i < 7; i++) {
      const date = new Date(today);
      date.setDate(date.getDate() + i);
      const day = date.toLocaleDateString('en-US', { weekday: 'long' });

      if (availability?.[day]) {
        const times = availability[day]; // e.g., ['10:00', '10:30']
        const slots = times.map(time => ({ time, isBooked: false }));
        await Slot.updateOne(
          { doctorId: doc._id, date: date.toISOString().split('T')[0] },
          { doctorId: doc._id, date: date.toISOString().split('T')[0], slots },
          { upsert: true }
        );
      }
    }
  }
};
cron.schedule('0 0 * * *', generateSlots); // Run daily at midnight


app.put('/api/change-password', verifyToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = await User.findById(req.user.id) || await Doctor.findById(req.user.id);
  const isMatch = await bcrypt.compare(oldPassword, user.password);
  if (!isMatch) return res.status(400).json({ error: 'Old password incorrect' });

  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();
  res.json({ message: 'Password changed' });
});




app.post('/api/logout', verifyToken, (req, res) => {
  const token = req.headers['authorization'];
  blacklist.add(token);
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/admin/users', verifyToken, requireRole('admin'), async (req, res) => {
  const users = await User.find();
  res.json(users);
});

app.get('/api/admin/doctors', verifyToken, requireRole('admin'), async (req, res) => {
  const doctors = await Doctor.find();
  res.json(doctors);
});

app.delete('/api/admin/user/:id', verifyToken, requireRole('admin'), async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: 'User deleted' });
});

app.delete('/api/admin/doctor/:id', verifyToken, requireRole('admin'), async (req, res) => {
  await Doctor.findByIdAndDelete(req.params.id);
  res.json({ message: 'Doctor deleted' });
});


