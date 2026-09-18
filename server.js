/**
 * AIT Admission Processing System - BACKEND (fichier unique) v3
 * Admin page served at GET /admin
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
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'aitadmin2026';
const UPLOAD_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ait-admission')
  .then(() => console.log('✅ MongoDB connecté'))
  .catch(err => { console.error('❌ MongoDB:', err.message); process.exit(1); });

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

const User = mongoose.model('User', userSchema);

const applicationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  programmeChoices: [{ rank: Number, programme: String, programmeCode: { type: String, default: '' } }],
  highestQualification: { type: String, default: '' },
  hasResults: { type: Boolean, default: true },
  awaitingResults: { type: Boolean, default: false },
  courseGrades: [{ course: String, grade: String, isCore: { type: Boolean, default: false } }],
  documents: [{
    filename: String, originalName: String, path: String, mimetype: String, size: Number,
    uploadedAt: { type: Date, default: Date.now },
  }],
  isComplete: { type: Boolean, default: false },
  submittedAt: Date,
}, { timestamps: true });

const Application = mongoose.model('Application', applicationSchema);

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false,
}));
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));

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

const adminAuth = (req, res, next) => {
  const password = req.headers['x-admin-password'] || req.query.password || req.body.password;
  if (password === ADMIN_PASSWORD) return next();
  return res.status(401).json({ success: false, message: 'Invalid admin password' });
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`),
});
const fileFilter = (req, file, cb) => {
  const allowed = /jpeg|jpg|png|gif|pdf|doc|docx/;
  const ext = allowed.test(path.extname(file.originalname).toLowerCase());
  const mime = allowed.test(file.mimetype) || file.mimetype === 'application/pdf' || file.mimetype.startsWith('image/');
  if (ext && mime) cb(null, true);
  else cb(new Error('Only images and documents allowed'));
};
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter });
const generateToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });

function getBaseUrl(req) {
  if (process.env.RENDER_EXTERNAL_URL) return process.env.RENDER_EXTERNAL_URL;
  if (process.env.BASE_URL) return process.env.BASE_URL;
  return `${req.protocol}://${req.get('host')}`;
}

// ==================== ADMIN HTML PAGE ====================
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AIT Admissions Admin</title>
  <link rel="icon" href="https://raw.githubusercontent.com/tekokossifelixkangnisoukpe5-ship-it/photo/main/33181-1.jpg" />
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f1f5f9; margin: 0; }
    .card { background: #fff; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  </style>
</head>
<body>
  <div id="app"></div>
  <script>
    const API = window.location.origin + '/api';
    const LOGO = 'https://raw.githubusercontent.com/tekokossifelixkangnisoukpe5-ship-it/photo/main/AIT%20logo.png';
    let adminPwd = sessionStorage.getItem('ait_admin_pwd') || '';
    let apps = [];
    let selected = null;
    let search = '';
    let loading = false;
    let error = '';

    async function api(method, path, body, headers = {}) {
      const h = { ...headers };
      if (adminPwd) h['x-admin-password'] = adminPwd;
      if (body && !(body instanceof FormData)) h['Content-Type'] = 'application/json';
      const res = await fetch(API + path, {
        method,
        headers: h,
        body: body ? (body instanceof FormData ? body : JSON.stringify(body)) : undefined,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || 'Error ' + res.status);
      return data;
    }

    function statusColor(s) {
      return ({
        draft: 'bg-gray-200 text-gray-700',
        submitted: 'bg-blue-100 text-blue-800',
        under_review: 'bg-yellow-100 text-yellow-800',
        accepted: 'bg-green-100 text-green-800',
        rejected: 'bg-red-100 text-red-800',
      })[s] || 'bg-gray-100';
    }

    async function doLogin(e) {
      e.preventDefault();
      const pwd = document.getElementById('pwd').value;
      error = ''; loading = true; render();
      try {
        await api('POST', '/admin/login', { password: pwd });
        adminPwd = pwd;
        sessionStorage.setItem('ait_admin_pwd', pwd);
        await loadApps();
      } catch (err) {
        error = err.message;
        adminPwd = '';
        sessionStorage.removeItem('ait_admin_pwd');
      }
      loading = false; render();
    }

    async function loadApps() {
      loading = true; error = ''; render();
      try {
        const data = await api('GET', '/admin/applications');
        apps = data.applications || [];
      } catch (err) {
        error = err.message;
        if (err.message.includes('Invalid') || err.message.includes('password')) {
          adminPwd = '';
          sessionStorage.removeItem('ait_admin_pwd');
        }
      }
      loading = false; render();
    }

    async function changeStatus(userId, status) {
      try {
        await api('PATCH', '/admin/applications/' + userId + '/status', { status });
        await loadApps();
        if (selected && selected.userId === userId) selected.applicationStatus = status;
        render();
      } catch (err) { alert(err.message); }
    }

    function filtered() {
      const q = search.toLowerCase();
      return apps.filter(a => !q ||
        (a.fullName || '').toLowerCase().includes(q) ||
        (a.email || '').toLowerCase().includes(q) ||
        (a.contactNumber || '').includes(q));
    }

    function render() {
      const el = document.getElementById('app');
      if (!adminPwd) {
        el.innerHTML = \`
        <div class="min-h-screen flex items-center justify-center px-4">
          <form onsubmit="doLogin(event)" class="card p-8 max-w-sm w-full space-y-4">
            <img src="\${LOGO}" class="w-16 h-16 mx-auto object-contain" alt="AIT" />
            <h1 class="text-xl font-bold text-center" style="color:#0A4D68">AIT Admissions Admin</h1>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Admin Password</label>
              <input id="pwd" type="password" required class="w-full border border-gray-300 rounded-lg px-3 py-2.5 outline-none focus:ring-2 focus:ring-teal-600" />
            </div>
            \${error ? '<p class="text-red-500 text-sm">' + error + '</p>' : ''}
            <button type="submit" class="w-full text-white font-semibold py-3 rounded-xl" style="background:#0A4D68" \${loading ? 'disabled' : ''}>
              \${loading ? 'Loading...' : 'Access Admin'}
            </button>
          </form>
        </div>\`;
        return;
      }

      const list = filtered();
      el.innerHTML = \`
      <div class="min-h-screen">
        <div class="text-white px-4 py-4 flex flex-wrap items-center justify-between gap-2" style="background:#0A4D68">
          <div class="flex items-center gap-3">
            <img src="\${LOGO}" class="w-10 h-10 object-contain bg-white rounded-full p-0.5" alt="AIT" />
            <h1 class="font-bold text-lg">AIT Admissions Admin</h1>
          </div>
          <div class="flex gap-2">
            <button onclick="loadApps()" class="bg-white/20 hover:bg-white/30 px-3 py-1.5 rounded-lg text-sm">Refresh</button>
            <button onclick="adminPwd='';sessionStorage.removeItem('ait_admin_pwd');render()" class="bg-white/20 hover:bg-white/30 px-3 py-1.5 rounded-lg text-sm">Logout</button>
          </div>
        </div>
        <div class="max-w-6xl mx-auto px-3 sm:px-4 py-4">
          <div class="mb-4 flex flex-col sm:flex-row gap-2 sm:items-center justify-between">
            <p class="font-semibold text-gray-700">All Students (\${list.length})</p>
            <input type="search" value="\${search.replace(/"/g, '&quot;')}" oninput="search=this.value;render()" placeholder="Search student..."
              class="border border-gray-300 rounded-lg px-3 py-2 text-sm w-full sm:w-64 outline-none" />
          </div>
          \${loading ? '<p class="text-center text-gray-500 py-8">Loading...</p>' : ''}
          \${!loading && list.length === 0 ? '<p class="text-center text-gray-500 py-8">No applications yet</p>' : ''}
          <div class="grid gap-3">
            \${list.map(a => \`
              <div class="card p-4 cursor-pointer hover:shadow-md transition" onclick='selected=\${JSON.stringify(a).replace(/'/g, "&#39;")};render()'>
                <div class="flex gap-3 items-start">
                  <div class="w-14 h-14 rounded-lg overflow-hidden bg-gray-100 flex-shrink-0 border">
                    \${a.photo ? '<img src="'+a.photo+'" class="w-full h-full object-cover" />' : '<div class="w-full h-full flex items-center justify-center text-gray-400 text-xs">N/A</div>'}
                  </div>
                  <div class="flex-1 min-w-0">
                    <div class="flex flex-wrap items-center gap-2 mb-1">
                      <h3 class="font-semibold text-gray-900 truncate">\${a.fullName || '—'}</h3>
                      <span class="text-xs px-2 py-0.5 rounded-full font-medium \${statusColor(a.applicationStatus)}">\${a.applicationStatus}</span>
                    </div>
                    <p class="text-sm text-gray-600 truncate">\${a.email || ''}</p>
                    <p class="text-sm text-gray-500">\${a.contactNumber || ''} · \${a.countryOfOrigin || ''}</p>
                    <p class="text-xs text-gray-400 mt-1">
                      \${(a.programmeChoices && a.programmeChoices[0] && a.programmeChoices[0].programme) || 'No programme'} · \${(a.documents && a.documents.length) || 0} doc(s)
                    </p>
                  </div>
                </div>
              </div>
            \`).join('')}
          </div>
        </div>
        \${selected ? renderModal() : ''}
      </div>\`;
    }

    function renderModal() {
      const a = selected;
      return \`
      <div class="fixed inset-0 bg-black/50 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4" onclick="if(event.target===this){selected=null;render()}">
        <div class="bg-white w-full sm:max-w-2xl sm:rounded-2xl rounded-t-2xl max-h-[92vh] overflow-y-auto" onclick="event.stopPropagation()">
          <div class="sticky top-0 bg-white border-b px-4 py-3 flex justify-between items-center z-10">
            <h2 class="font-bold" style="color:#0A4D68">Student Details</h2>
            <button onclick="selected=null;render()" class="text-gray-500 text-2xl leading-none">&times;</button>
          </div>
          <div class="p-4 sm:p-6 space-y-5">
            <div class="flex gap-4 items-start">
              <div class="w-24 h-28 rounded-lg overflow-hidden bg-gray-100 border flex-shrink-0">
                \${a.photo ? '<img src="'+a.photo+'" class="w-full h-full object-cover" />' : '<div class="w-full h-full flex items-center justify-center text-gray-400 text-sm">No photo</div>'}
              </div>
              <div>
                <h3 class="text-lg font-bold text-gray-900">\${a.fullName || '—'}</h3>
                <p class="text-sm text-gray-600">\${a.email || ''}</p>
                <span class="inline-block mt-2 text-xs px-2.5 py-1 rounded-full font-medium \${statusColor(a.applicationStatus)}">\${a.applicationStatus}</span>
              </div>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
              <div><span class="text-gray-500">Phone:</span> <strong>\${a.contactNumber || '—'}</strong></div>
              <div><span class="text-gray-500">Other:</span> <strong>\${a.otherContact || '—'}</strong></div>
              <div><span class="text-gray-500">WhatsApp:</span> <strong>\${a.whatsappContact || '—'}</strong></div>
              <div><span class="text-gray-500">Gender:</span> <strong>\${a.gender || '—'}</strong></div>
              <div><span class="text-gray-500">DOB:</span> <strong>\${a.dateOfBirth ? String(a.dateOfBirth).split('T')[0] : '—'}</strong></div>
              <div><span class="text-gray-500">Country:</span> <strong>\${a.countryOfOrigin || '—'}</strong></div>
              <div class="sm:col-span-2"><span class="text-gray-500">Address:</span> <strong>\${a.homeAddress || '—'}</strong></div>
              <div><span class="text-gray-500">Qualification:</span> <strong>\${a.highestQualification || '—'}</strong></div>
              <div><span class="text-gray-500">Submitted:</span> <strong>\${a.submittedAt ? new Date(a.submittedAt).toLocaleString() : '—'}</strong></div>
            </div>
            <div>
              <h4 class="font-semibold mb-2 text-sm border-b-2 pb-1" style="color:#0A4D68;border-color:#0A4D68">Programme Choices</h4>
              <ol class="list-decimal list-inside text-sm space-y-1">
                \${(a.programmeChoices || []).map(p => '<li>'+ (p.programme || '') +'</li>').join('') || '<li class="text-gray-400">—</li>'}
              </ol>
            </div>
            <div>
              <h4 class="font-semibold mb-2 text-sm border-b-2 pb-1" style="color:#0A4D68;border-color:#0A4D68">Grades</h4>
              <div class="grid grid-cols-2 gap-1 text-sm">
                \${(a.courseGrades || []).map(g => '<div class="flex justify-between bg-slate-50 rounded px-2 py-1"><span>'+g.course+'</span><strong>'+g.grade+'</strong></div>').join('') || '<span class="text-gray-400">—</span>'}
              </div>
            </div>
            <div>
              <h4 class="font-semibold mb-2 text-sm border-b-2 pb-1" style="color:#0A4D68;border-color:#0A4D68">Documents</h4>
              \${(a.documents && a.documents.length) ? '<ul class="space-y-2">' + a.documents.map(d => '<li><a href="'+(d.url || d.path)+'" target="_blank" class="text-sm underline break-all" style="color:#0A4D68">📄 '+(d.originalName || d.filename)+'</a></li>').join('') + '</ul>' : '<p class="text-sm text-gray-400">No documents</p>'}
            </div>
            <div>
              <h4 class="font-semibold mb-2 text-sm border-b-2 pb-1" style="color:#0A4D68;border-color:#0A4D68">Change status</h4>
              <div class="flex flex-wrap gap-2">
                \${['draft','submitted','under_review','accepted','rejected'].map(s =>
                  '<button onclick="changeStatus(\\''+a.userId+'\\',\\''+s+'\\')" class="text-xs px-3 py-1.5 rounded-full font-medium border '+statusColor(s)+(a.applicationStatus===s?' ring-2 ring-offset-1':'')+'">'+s+'</button>'
                ).join('')}
              </div>
            </div>
          </div>
        </div>
      </div>\`;
    }

    if (adminPwd) loadApps();
    else render();
  </script>
</body>
</html>`;

// ==================== ROUTES ====================
app.get('/', (req, res) => {
  res.json({ success: true, message: 'AIT Admission API v3', admin: '/admin', version: '3.0.0' });
});

// PAGE ADMIN (HTML servi par le backend)
app.get('/admin', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(ADMIN_HTML);
});

// ---------- AUTH ----------
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@')) return res.status(400).json({ success: false, message: 'Valid email required' });
    let user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      user = await User.create({
        email: email.toLowerCase().trim(),
        firstName: 'Applicant', lastName: 'New', contactNumber: '0000000000', gender: 'Male',
        dateOfBirth: new Date('2000-01-01'), whatsappContact: '0000000000', homeAddress: 'To be updated',
        countryOfOrigin: 'Ghana', applicationStatus: 'draft', currentStep: 1,
      });
      await Application.create({ user: user._id, programmeChoices: [], courseGrades: [], documents: [] });
    }
    const token = generateToken(user._id.toString());
    res.json({
      success: true, token,
      user: {
        id: user._id, email: user.email, firstName: user.firstName, middleName: user.middleName,
        lastName: user.lastName, photo: user.photo, currentStep: user.currentStep, applicationStatus: user.applicationStatus,
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
        id: user._id, email: user.email, firstName: user.firstName, middleName: user.middleName,
        lastName: user.lastName, photo: user.photo, contactNumber: user.contactNumber, otherContact: user.otherContact,
        gender: user.gender, dateOfBirth: user.dateOfBirth, whatsappContact: user.whatsappContact,
        homeAddress: user.homeAddress, countryOfOrigin: user.countryOfOrigin,
        currentStep: user.currentStep, applicationStatus: user.applicationStatus,
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
      success: true, message: 'Basic information updated',
      user: {
        id: user._id, email: user.email, firstName: user.firstName, middleName: user.middleName,
        lastName: user.lastName, photo: user.photo, contactNumber: user.contactNumber, otherContact: user.otherContact,
        gender: user.gender, dateOfBirth: user.dateOfBirth, whatsappContact: user.whatsappContact,
        homeAddress: user.homeAddress, countryOfOrigin: user.countryOfOrigin, currentStep: user.currentStep,
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
    if (!application) application = await Application.create({ user: req.user._id });
    application.programmeChoices = programmeChoices.map((c, i) => ({
      rank: i + 1, programme: c.programme, programmeCode: c.programmeCode || '',
    }));
    await application.save();
    const user = await User.findById(req.user._id);
    if (user) { user.currentStep = Math.max(user.currentStep, 3); await user.save(); }
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
    if (user) { user.currentStep = Math.max(user.currentStep, 4); await user.save(); }
    res.json({ success: true, message: 'Grades updated', application });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/application/documents', protect, upload.array('documents', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) return res.status(400).json({ success: false, message: 'No documents uploaded' });
    let application = await Application.findOne({ user: req.user._id });
    if (!application) application = await Application.create({ user: req.user._id });
    const newDocs = req.files.map(f => ({
      filename: f.filename, originalName: f.originalname, path: `/uploads/${f.filename}`,
      mimetype: f.mimetype, size: f.size, uploadedAt: new Date(),
    }));
    application.documents.push(...newDocs);
    await application.save();
    const user = await User.findById(req.user._id);
    if (user) { user.currentStep = Math.max(user.currentStep, 5); await user.save(); }
    res.json({ success: true, message: 'Documents uploaded', documents: application.documents });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error uploading documents' });
  }
});

app.delete('/api/application/documents/:filename', protect, async (req, res) => {
  try {
    const { filename } = req.params;
    const application = await Application.findOne({ user: req.user._id });
    if (!application) return res.status(404).json({ success: false, message: 'Application not found' });
    const doc = application.documents.find(d => d.filename === filename);
    if (!doc) return res.status(404).json({ success: false, message: 'Document not found' });
    const filePath = path.join(UPLOAD_DIR, filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    application.documents = application.documents.filter(d => d.filename !== filename);
    await application.save();
    res.json({ success: true, message: 'Document deleted', documents: application.documents });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error deleting document' });
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
    if (user) { user.applicationStatus = 'submitted'; user.currentStep = 6; await user.save(); }
    res.json({ success: true, message: 'Application submitted successfully!', application });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ---------- ADMIN API ----------
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (password === ADMIN_PASSWORD) return res.json({ success: true, message: 'Admin authenticated' });
  return res.status(401).json({ success: false, message: 'Wrong password' });
});

app.get('/api/admin/applications', adminAuth, async (req, res) => {
  try {
    const applications = await Application.find().populate('user', '-password').sort({ updatedAt: -1 });
    const base = getBaseUrl(req);
    const result = applications.map(app => {
      const u = app.user || {};
      return {
        applicationId: app._id,
        userId: u._id,
        email: u.email,
        firstName: u.firstName,
        middleName: u.middleName,
        lastName: u.lastName,
        fullName: `${u.firstName || ''} ${u.middleName || ''} ${u.lastName || ''}`.replace(/\s+/g, ' ').trim(),
        photo: u.photo ? `${base}${u.photo}` : null,
        contactNumber: u.contactNumber,
        otherContact: u.otherContact,
        gender: u.gender,
        dateOfBirth: u.dateOfBirth,
        whatsappContact: u.whatsappContact,
        homeAddress: u.homeAddress,
        countryOfOrigin: u.countryOfOrigin,
        applicationStatus: u.applicationStatus,
        currentStep: u.currentStep,
        programmeChoices: app.programmeChoices,
        highestQualification: app.highestQualification,
        hasResults: app.hasResults,
        awaitingResults: app.awaitingResults,
        courseGrades: app.courseGrades,
        documents: (app.documents || []).map(d => {
          const obj = d.toObject ? d.toObject() : d;
          return { ...obj, url: `${base}${obj.path}` };
        }),
        isComplete: app.isComplete,
        submittedAt: app.submittedAt,
        createdAt: app.createdAt,
        updatedAt: app.updatedAt,
      };
    });
    res.json({ success: true, count: result.length, applications: result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.patch('/api/admin/applications/:userId/status', adminAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const allowed = ['draft', 'submitted', 'under_review', 'accepted', 'rejected'];
    if (!allowed.includes(status)) return res.status(400).json({ success: false, message: 'Invalid status' });
    const user = await User.findByIdAndUpdate(req.params.userId, { applicationStatus: status }, { new: true });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ success: false, message: err.message || 'Internal Server Error' });
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`🚀 AIT Backend v3 on port ${PORT}`);
  console.log(`🔐 Admin page: /admin`);
});
