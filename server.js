/**
 * AIT Admission Processing System - BACKEND (fichier unique)
 * Accra Institute of Technology
 * 
 * Déploiement Render :
 *   Build Command  : npm install
 *   Start Command  : node server.js
 * 
 * Variables d'environnement requises :
 *   MONGODB_URI, JWT_SECRET, FRONTEND_URL, PORT, NODE_ENV
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'ait_default_secret_change_me';
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Créer le dossier uploads s'il n'existe pas
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ==================== CONNEXION MONGODB ====================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ait-admission')
  .then(() => console.log('✅ MongoDB connecté'))
  .catch(err => {
    console.error('❌ Erreur MongoDB:', err.message);
    process.exit(1);
  });

// ==================== MODELS (tout dans ce fichier) ====================
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, select: false },
  firstName: { type: String, required: true, trim: true, default: 'Applicant' },
  middleName: { type: String, trim: true, default: '' },
  lastName: { type: String, required: true, trim: true, default: 'New' },
  photo: { type: String },
  contactNumber: { type: String, required: true, default: '0000000000' },
  otherContact: { type: String, default: '' },
  gender: { type: String, enum: ['Male', 'Female', 'Other'], default: 'Male' },
  dateOfBirth: { type: Date, default: new Date('2000-01-01') },
  whatsappContact: { type: String, required: true, default: '0000000000' },
  homeAddress: { type: String, required: true, default: 'To be updated' },
  countryOfOrigin: { type: String, required: true, default: 'Ghana' },
  isEmailVerified: { type: Boolean, default: false },
  applicationStatus: { type: String, enum: ['draft', 'submitted', 'under_review', 'accepted', 'rejected'], default: 'draft' },
  currentStep: { type: Number, default: 1 },
}, { timestamps: true });

userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || !this.password) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function (candidate) {
  if (!this.password) return false;
  return bcrypt.compare(candidate, this.password);
};

const User = mongoose.model('User', userSchema);

const applicationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  programmeChoices: [{
    rank: { type: Number, min: 1, max: 3 },
    programme: { type: String, required: true },
    programmeCode: { type: String, default: '' },
  }],
  highestQualification: { type: String, default: '' },
  hasResults: { type: Boolean, default: true },
  awaitingResults: { type: Boolean, default: false },
  courseGrades: [{
    course: { type: String, required: true },
    grade: { type: String, required: true },
    isCore: { type: Boolean, default: false },
  }],
  documents: [{
    filename: String,
    originalName: String,
    path: String,
    mimetype: String,
    size: Number,
    uploadedAt: { type: Date, default: Date.now },
  }],
  isComplete: { type: Boolean, default: false },
  submittedAt: Date,
}, { timestamps: true });

const Application = mongoose.model('Application', applicationSchema);

// ==================== MIDDLEWARE ====================
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));

// Auth middleware
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) return res.status(401).json({ success: false, message: 'Not authorized, no token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ success: false, message: 'User not found' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Not authorized, token failed' });
  }
};

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`),
});
const fileFilter = (req, file, cb) => {
  const allowed = /jpeg|jpg|png|gif|pdf|doc|docx/;
  const ext = allowed.test(path.extname(file.originalname).toLowerCase());
  const mime = allowed.test(file.mimetype) || file.mimetype === 'application/pdf' || file.mimetype.startsWith('image/');
  if (ext && mime) cb(null, true);
  else cb(new Error('Only images and documents (pdf, doc, docx) allowed'));
};
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter });

const generateToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });

// ==================== ROUTES ====================

// Santé
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'AIT Admission Processing System API (fichier unique)',
    version: '1.0.0',
  });
});

// ---------- AUTH ----------
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ success: false, message: 'Valid email required' });
    }
    let user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      user = await User.create({
        email: email.toLowerCase().trim(),
        firstName: 'Applicant',
        lastName: 'New',
        contactNumber: '0000000000',
        gender: 'Male',
        dateOfBirth: new Date('2000-01-01'),
        whatsappContact: '0000000000',
        homeAddress: 'To be updated',
        countryOfOrigin: 'Ghana',
        applicationStatus: 'draft',
        currentStep: 1,
      });
      await Application.create({ user: user._id, programmeChoices: [], courseGrades: [], documents: [] });
    }
    const token = generateToken(user._id.toString());
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        middleName: user.middleName,
        lastName: user.lastName,
        photo: user.photo,
        currentStep: user.currentStep,
        applicationStatus: user.applicationStatus,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

app.get('/api/auth/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const application = await Application.findOne({ user: user._id });
    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        middleName: user.middleName,
        lastName: user.lastName,
        photo: user.photo,
        contactNumber: user.contactNumber,
        otherContact: user.otherContact,
        gender: user.gender,
        dateOfBirth: user.dateOfBirth,
        whatsappContact: user.whatsappContact,
        homeAddress: user.homeAddress,
        countryOfOrigin: user.countryOfOrigin,
        currentStep: user.currentStep,
        applicationStatus: user.applicationStatus,
      },
      application,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ---------- APPLICATION ----------
app.get('/api/application', protect, async (req, res) => {
  try {
    const application = await Application.findOne({ user: req.user._id }).populate('user', '-password');
    if (!application) return res.status(404).json({ success: false, message: 'Application not found' });
    res.json({ success: true, application });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/application/basic-info', protect, upload.single('photo'), async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const { firstName, middleName, lastName, contactNumber, otherContact, gender, dateOfBirth, whatsappContact, homeAddress, countryOfOrigin } = req.body;

    if (firstName) user.firstName = firstName;
    if (middleName !== undefined) user.middleName = middleName;
    if (lastName) user.lastName = lastName;
    if (contactNumber) user.contactNumber = contactNumber;
    if (otherContact !== undefined) user.otherContact = otherContact;
    if (gender) user.gender = gender;
    if (dateOfBirth) user.dateOfBirth = new Date(dateOfBirth);
    if (whatsappContact) user.whatsappContact = whatsappContact;
    if (homeAddress) user.homeAddress = homeAddress;
    if (countryOfOrigin) user.countryOfOrigin = countryOfOrigin;
    user.currentStep = Math.max(user.currentStep, 2);

    if (req.file) {
      if (user.photo) {
        const old = path.join(UPLOAD_DIR, path.basename(user.photo));
        if (fs.existsSync(old)) fs.unlinkSync(old);
      }
      user.photo = `/uploads/${req.file.filename}`;
    }

    await user.save();
    res.json({
      success: true,
      message: 'Basic information updated',
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        middleName: user.middleName,
        lastName: user.lastName,
        photo: user.photo,
        contactNumber: user.contactNumber,
        otherContact: user.otherContact,
        gender: user.gender,
        dateOfBirth: user.dateOfBirth,
        whatsappContact: user.whatsappContact,
        homeAddress: user.homeAddress,
        countryOfOrigin: user.countryOfOrigin,
        currentStep: user.currentStep,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error updating basic info' });
  }
});

app.put('/api/application/programme-choices', protect, async (req, res) => {
  try {
    const { programmeChoices } = req.body;
    if (!Array.isArray(programmeChoices) || programmeChoices.length < 1 || programmeChoices.length > 3) {
      return res.status(400).json({ success: false, message: '1 to 3 programme choices required' });
    }
    let application = await Application.findOne({ user: req.user._id });
    if (!application) {
      application = await Application.create({ user: req.user._id });
    }
    application.programmeChoices = programmeChoices.map((c, i) => ({
      rank: i + 1,
      programme: c.programme,
      programmeCode: c.programmeCode || '',
    }));
    await application.save();
    const user = await User.findById(req.user._id);
    if (user) {
      user.currentStep = Math.max(user.currentStep, 3);
      await user.save();
    }
    res.json({ success: true, message: 'Programme choices updated', application });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/application/grades', protect, async (req, res) => {
  try {
    const { highestQualification, hasResults, awaitingResults, courseGrades } = req.body;
    let application = await Application.findOne({ user: req.user._id });
    if (!application) application = await Application.create({ user: req.user._id });

    if (highestQualification !== undefined) application.highestQualification = highestQualification;
    if (hasResults !== undefined) application.hasResults = hasResults;
    if (awaitingResults !== undefined) application.awaitingResults = awaitingResults;
    if (Array.isArray(courseGrades)) application.courseGrades = courseGrades;

    await application.save();
    const user = await User.findById(req.user._id);
    if (user) {
      user.currentStep = Math.max(user.currentStep, 4);
      await user.save();
    }
    res.json({ success: true, message: 'Grades updated', application });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/application/documents', protect, upload.array('documents', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ success: false, message: 'No documents uploaded' });
    }
    let application = await Application.findOne({ user: req.user._id });
    if (!application) application = await Application.create({ user: req.user._id });

    const newDocs = req.files.map(f => ({
      filename: f.filename,
      originalName: f.originalname,
      path: `/uploads/${f.filename}`,
      mimetype: f.mimetype,
      size: f.size,
      uploadedAt: new Date(),
    }));
    application.documents.push(...newDocs);
    await application.save();

    const user = await User.findById(req.user._id);
    if (user) {
      user.currentStep = Math.max(user.currentStep, 5);
      await user.save();
    }
    res.json({ success: true, message: 'Documents uploaded', documents: application.documents });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error uploading documents' });
  }
});

app.post('/api/application/submit', protect, async (req, res) => {
  try {
    const application = await Application.findOne({ user: req.user._id });
    if (!application) return res.status(404).json({ success: false, message: 'Application not found' });
    application.isComplete = true;
    application.submittedAt = new Date();
    await application.save();
    const user = await User.findById(req.user._id);
    if (user) {
      user.applicationStatus = 'submitted';
      user.currentStep = 6;
      await user.save();
    }
    res.json({ success: true, message: 'Application submitted successfully. Thanks for your cooperation!', application });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Erreurs
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ success: false, message: err.message || 'Internal Server Error' });
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`🚀 AIT Backend (fichier unique) sur le port ${PORT}`);
  console.log(`🌍 Env: ${process.env.NODE_ENV || 'development'}`);
});
