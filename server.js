/**
 * AIT Admission Backend v4 - single file
 * Admin: GET /admin | Chat + full application fields
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
  applyingFor: { type: String, default: '' }, // campus | open_university
  programType: { type: String, default: '' }, // undergraduate | postgraduate | certificate | diploma
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

const chatSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  sender: { type: String, enum: ['student', 'admin'], required: true },
  text: { type: String, required: true, trim: true },
}, { timestamps: true });
const ChatMessage = mongoose.model('ChatMessage', chatSchema);

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' }, contentSecurityPolicy: false }));
const _fo = (process.env.FRONTEND_URL || '*').replace(/\/$/, '');
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || _fo === '*' || origin.replace(/\/$/, '') === _fo) return callback(null, true);
    return callback(null, true); // allow in production admissions portal
  },
  credentials: true,
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));

const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer'))
    token = req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Not authorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ success: false, message: 'User not found' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: 'Token failed' });
  }
};
const adminAuth = (req, res, next) => {
  const password = req.headers['x-admin-password'] || req.query.password || (req.body && req.body.password);
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
  if (ext && mime) cb(null, true); else cb(new Error('Invalid file type'));
};
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 }, fileFilter });
const generateToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
function getBaseUrl(req) {
  if (process.env.RENDER_EXTERNAL_URL) return process.env.RENDER_EXTERNAL_URL;
  if (process.env.BASE_URL) return process.env.BASE_URL;
  return `${req.protocol}://${req.get('host')}`;
}

// ===== ADMIN HTML (with Conversations tab) =====
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AIT Admissions Admin</title>
<link rel="icon" href="https://raw.githubusercontent.com/tekokossifelixkangnisoukpe5-ship-it/photo/main/AIT%20logo.png"/>
<script src="https://cdn.tailwindcss.com"></script>
<style>body{font-family:Segoe UI,system-ui,sans-serif;background:#f1f5f9;margin:0}.card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.08)}</style>
</head><body><div id="app"></div>
<script>
const API = location.origin + '/api';
const LOGO = 'https://raw.githubusercontent.com/tekokossifelixkangnisoukpe5-ship-it/photo/main/AIT%20logo.png';
const STAFF = 'https://raw.githubusercontent.com/tekokossifelixkangnisoukpe5-ship-it/photo/main/33181-1.jpg';
let adminPwd = sessionStorage.getItem('ait_admin_pwd') || '';
let apps = [], selected = null, search = '', loading = false, error = '', tab = 'details', chatMsgs = [], chatText = '', chatPoll = null;

async function api(method, path, body) {
  const h = {};
  if (adminPwd) h['x-admin-password'] = adminPwd;
  if (body) h['Content-Type'] = 'application/json';
  const r = await fetch(API + path, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.message || ('Error ' + r.status));
  return d;
}
function sc(s) {
  return ({ draft: 'bg-gray-200 text-gray-700', submitted: 'bg-blue-100 text-blue-800', under_review: 'bg-yellow-100 text-yellow-800', accepted: 'bg-green-100 text-green-800', rejected: 'bg-red-100 text-red-800' })[s] || 'bg-gray-100';
}
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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
    const d = await api('GET', '/admin/applications');
    apps = d.applications || [];
  } catch (err) {
    error = err.message;
    if (/Invalid|password|Wrong/i.test(err.message)) {
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
    if (selected && String(selected.userId) === String(userId)) selected.applicationStatus = status;
    render();
  } catch (e) { alert(e.message); }
}

let pendingDelete = null;

function askDelete(userId, name) {
  pendingDelete = { userId: userId, name: name || 'this student' };
  render();
}

function cancelDelete() {
  pendingDelete = null;
  render();
}

async function confirmDelete() {
  if (!pendingDelete) return;
  var userId = pendingDelete.userId;
  var name = pendingDelete.name;
  pendingDelete = null;
  try {
    await api('DELETE', '/admin/applications/' + userId);
    if (selected && String(selected.userId) === String(userId)) { selected = null; stopPoll(); }
    await loadApps();
  } catch (e) {
    alert(e.message);
    render();
  }
}

function deleteStudent(userId, name) {
  askDelete(userId, name);
}

function renderDeleteModal() {
  if (!pendingDelete) return '';
  var name = esc(pendingDelete.name);
  return '<div class="fixed inset-0 z-[60] flex items-center justify-center p-4" style="background:rgba(15,23,42,0.55)">' +
    '<div class="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden">' +
      '<div class="px-6 pt-6 pb-2">' +
        '<div class="w-12 h-12 rounded-full bg-red-100 flex items-center justify-center mb-4">' +
          '<svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>' +
        '</div>' +
        '<h3 class="text-lg font-bold text-gray-900 mb-2">Delete student record</h3>' +
        '<p class="text-sm text-gray-600 leading-relaxed">You are about to permanently delete <strong>' + name + '</strong>. This will remove their account, application, uploaded documents, photo and chat history. This action cannot be undone.</p>' +
      '</div>' +
      '<div class="px-6 py-4 bg-gray-50 flex flex-col-reverse sm:flex-row gap-2 sm:justify-end">' +
        '<button type="button" id="btn-cancel-del" class="px-4 py-2.5 rounded-lg text-sm font-medium text-gray-700 bg-white border border-gray-300 hover:bg-gray-50">Cancel</button>' +
        '<button type="button" id="btn-confirm-del" class="px-4 py-2.5 rounded-lg text-sm font-semibold text-white bg-red-600 hover:bg-red-700">Delete permanently</button>' +
      '</div>' +
    '</div></div>';
}

async function loadChat(userId) {
  try {
    const d = await api('GET', '/admin/chat/' + userId);
    chatMsgs = d.messages || [];
    renderChatBox();
  } catch (e) { chatMsgs = []; }
}
async function sendChat() {
  if (!chatText.trim() || !selected) return;
  const txt = chatText.trim(); chatText = '';
  try {
    await api('POST', '/admin/chat/' + selected.userId, { text: txt });
    await loadChat(selected.userId);
  } catch (e) { alert(e.message); }
}
function startPoll() {
  stopPoll();
  if (selected && tab === 'chat') chatPoll = setInterval(function(){ loadChat(selected.userId); }, 4000);
}
function stopPoll() {
  if (chatPoll) { clearInterval(chatPoll); chatPoll = null; }
}

function filtered() {
  const q = search.toLowerCase();
  return apps.filter(function(a) {
    return !q || (a.fullName || '').toLowerCase().includes(q) || (a.email || '').toLowerCase().includes(q) || (a.contactNumber || '').includes(q);
  });
}

function openStudent(a) {
  selected = a; tab = 'details'; chatMsgs = []; render(); loadChat(a.userId);
}
function openStudentById(id) {
  var a = apps.find(function(x){ return String(x.userId) === String(id); });
  if (a) openStudent(a);
}
function setTab(t) {
  tab = t; render();
  if (t === 'chat' && selected) { loadChat(selected.userId); startPoll(); }
  else stopPoll();
}

function renderChatBox() {
  var box = document.getElementById('chat-msgs');
  if (!box) return;
  if (!chatMsgs.length) {
    box.innerHTML = '<p class="text-gray-400 text-sm text-center">No messages yet</p>';
    return;
  }
  box.innerHTML = chatMsgs.map(function(m) {
    var side = m.sender === 'admin' ? 'justify-end' : 'justify-start';
    var bg = m.sender === 'admin' ? 'bg-teal-600 text-white' : 'bg-gray-100 text-gray-800';
    return '<div class="flex ' + side + ' mb-2"><div class="max-w-[80%] rounded-2xl px-3 py-2 text-sm ' + bg + '"><div>' + esc(m.text) + '</div><div class="text-[10px] opacity-70 mt-0.5">' + new Date(m.createdAt).toLocaleString() + '</div></div></div>';
  }).join('');
  box.scrollTop = box.scrollHeight;
}

function render() {
  var el = document.getElementById('app');
  if (!adminPwd) {
    el.innerHTML = '<div class="min-h-screen flex items-center justify-center px-4"><form onsubmit="doLogin(event)" class="card p-8 max-w-sm w-full space-y-4">' +
      '<img src="' + LOGO + '" class="w-16 h-16 mx-auto object-contain" alt="AIT"/>' +
      '<h1 class="text-xl font-bold text-center" style="color:#0A4D68">AIT Admissions Admin</h1>' +
      '<div><label class="block text-sm font-medium mb-1">Admin Password</label>' +
      '<input id="pwd" type="password" required class="w-full border rounded-lg px-3 py-2.5"/></div>' +
      (error ? '<p class="text-red-500 text-sm">' + esc(error) + '</p>' : '') +
      '<button class="w-full text-white font-semibold py-3 rounded-xl" style="background:#0A4D68"' + (loading ? ' disabled' : '') + '>' + (loading ? 'Loading...' : 'Access Admin') + '</button></form></div>';
    return;
  }
  var list = filtered();
  var cards = list.map(function(a) {
    var photo = a.photo
      ? '<img src="' + esc(a.photo) + '" class="w-full h-full object-cover"/>'
      : '<div class="w-full h-full flex items-center justify-center text-xs text-gray-400">N/A</div>';
    var prog = (a.programmeChoices && a.programmeChoices[0] && a.programmeChoices[0].programme) || 'No programme';
    var ndocs = (a.documents && a.documents.length) || 0;
    return '<div class="card p-4 hover:shadow-md flex gap-3 items-start">' +
      '<div class="flex gap-3 flex-1 min-w-0 cursor-pointer" data-open="' + esc(String(a.userId)) + '">' +
        '<div class="w-14 h-14 rounded-lg overflow-hidden bg-gray-100 border flex-shrink-0">' + photo + '</div>' +
        '<div class="flex-1 min-w-0">' +
          '<div class="flex flex-wrap gap-2 items-center mb-1"><h3 class="font-semibold truncate">' + esc(a.fullName || '—') + '</h3>' +
          '<span class="text-xs px-2 py-0.5 rounded-full ' + sc(a.applicationStatus) + '">' + esc(a.applicationStatus) + '</span></div>' +
          '<p class="text-sm text-gray-600 truncate">' + esc(a.email || '') + '</p>' +
          '<p class="text-sm text-gray-500">' + esc(a.contactNumber || '') + ' · ' + esc(a.countryOfOrigin || '') + '</p>' +
          '<p class="text-xs text-gray-400 mt-1">' + esc(prog) + ' · ' + ndocs + ' doc(s)</p>' +
        '</div>' +
      '</div>' +
      '<button type="button" class="flex-shrink-0 bg-red-600 hover:bg-red-700 text-white text-xs font-semibold px-3 py-2 rounded-lg" data-del="' + esc(String(a.userId)) + '" data-name="' + esc(a.fullName || a.email || 'student') + '">Delete</button>' +
    '</div>';
  }).join('');

  el.innerHTML = '<div class="min-h-screen">' +
    '<div class="text-white px-4 py-4 flex flex-wrap items-center justify-between gap-2" style="background:#0A4D68">' +
      '<div class="flex items-center gap-3"><img src="' + LOGO + '" class="w-10 h-10 object-contain bg-white rounded-full p-0.5"/><h1 class="font-bold text-lg">AIT Admissions Admin</h1></div>' +
      '<div class="flex gap-2">' +
        '<button type="button" id="btn-refresh" class="bg-white/20 px-3 py-1.5 rounded-lg text-sm">Refresh</button>' +
        '<button type="button" id="btn-logout" class="bg-white/20 px-3 py-1.5 rounded-lg text-sm">Logout</button>' +
      '</div></div>' +
    '<div class="max-w-6xl mx-auto px-3 py-4">' +
      '<div class="mb-4 flex flex-col sm:flex-row gap-2 justify-between">' +
        '<p class="font-semibold">All Students (' + list.length + ')</p>' +
        '<input type="search" id="search-input" value="' + esc(search) + '" placeholder="Search..." class="border rounded-lg px-3 py-2 text-sm w-full sm:w-64"/>' +
      '</div>' +
      (loading ? '<p class="text-center text-gray-500 py-8">Loading...</p>' : '') +
      (!loading && !list.length ? '<p class="text-center text-gray-500 py-8">No applications</p>' : '') +
      '<div class="grid gap-3">' + cards + '</div>' +
    '</div>' +
    (selected ? renderModal() : '') + renderDeleteModal() +
  '</div>';

  // wire events (no inline handlers that conflict)
  var ref = document.getElementById('btn-refresh');
  if (ref) ref.onclick = function(){ loadApps(); };
  var lo = document.getElementById('btn-logout');
  if (lo) lo.onclick = function(){ stopPoll(); adminPwd=''; sessionStorage.removeItem('ait_admin_pwd'); render(); };
  var si = document.getElementById('search-input');
  if (si) si.oninput = function(){ search = this.value; render(); };

  document.querySelectorAll('[data-open]').forEach(function(node){
    node.onclick = function(e){ e.stopPropagation(); openStudentById(node.getAttribute('data-open')); };
  });
  document.querySelectorAll('[data-del]').forEach(function(btn){
    btn.onclick = function(e){
      e.preventDefault();
      e.stopPropagation();
      deleteStudent(btn.getAttribute('data-del'), btn.getAttribute('data-name') || 'student');
    };
  });

  if (selected && tab === 'chat') { renderChatBox(); startPoll(); }
  wireModal();
  var cd = document.getElementById('btn-cancel-del');
  if (cd) cd.onclick = function(){ cancelDelete(); };
  var cfd = document.getElementById('btn-confirm-del');
  if (cfd) cfd.onclick = function(){ confirmDelete(); };
}

function renderModal() {
  var a = selected;
  var photo = a.photo
    ? '<img src="' + esc(a.photo) + '" class="w-full h-full object-cover"/>'
    : '<div class="w-full h-full flex items-center justify-center text-sm text-gray-400">No photo</div>';
  var tabs = '<div class="flex border-b">' +
    '<button type="button" data-tab="details" class="flex-1 py-2.5 text-sm font-medium ' + (tab==='details'?'border-b-2 text-teal-700 border-teal-600':'text-gray-500') + '">Details</button>' +
    '<button type="button" data-tab="chat" class="flex-1 py-2.5 text-sm font-medium ' + (tab==='chat'?'border-b-2 text-teal-700 border-teal-600':'text-gray-500') + '">Conversations</button></div>';

  var body = tab === 'details' ? renderDetails(a) : renderChatTab(a);
  return '<div class="fixed inset-0 bg-black/50 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4" id="modal-backdrop">' +
    '<div class="bg-white w-full sm:max-w-2xl sm:rounded-2xl rounded-t-2xl max-h-[92vh] overflow-y-auto" id="modal-panel">' +
      '<div class="sticky top-0 bg-white border-b px-4 py-3 flex justify-between items-center z-10">' +
        '<h2 class="font-bold" style="color:#0A4D68">Student</h2>' +
        '<button type="button" id="modal-close" class="text-2xl text-gray-500">&times;</button></div>' +
      tabs + body +
    '</div></div>';
}

function renderDetails(a) {
  var progs = (a.programmeChoices || []).map(function(p,i){ return '<li>' + esc(p.programme || '') + '</li>'; }).join('') || '<li class="text-gray-400">—</li>';
  var grades = (a.courseGrades || []).map(function(g){
    return '<div class="flex justify-between bg-slate-50 rounded px-2 py-1"><span>' + esc(g.course) + '</span><strong>' + esc(g.grade) + '</strong></div>';
  }).join('') || '<span class="text-gray-400">—</span>';
  var docs = (a.documents && a.documents.length)
    ? a.documents.map(function(d){ return '<a href="' + esc(d.url || d.path) + '" target="_blank" class="block text-sm underline mb-1" style="color:#0A4D68">📄 ' + esc(d.originalName || d.filename) + '</a>'; }).join('')
    : '<p class="text-sm text-gray-400">No documents</p>';
  var statuses = ['draft','submitted','under_review','accepted','rejected'].map(function(s){
    return '<button type="button" data-status="' + s + '" class="text-xs px-3 py-1.5 rounded-full border ' + sc(s) + (a.applicationStatus===s?' ring-2':'') + '">' + s + '</button>';
  }).join('');

  return '<div class="p-4 sm:p-6 space-y-4">' +
    '<div class="flex gap-4"><div class="w-24 h-28 rounded-lg overflow-hidden bg-gray-100 border flex-shrink-0">' + (a.photo ? '<img src="'+esc(a.photo)+'" class="w-full h-full object-cover"/>' : '<div class="w-full h-full flex items-center justify-center text-sm text-gray-400">No photo</div>') + '</div>' +
    '<div><h3 class="text-lg font-bold">' + esc(a.fullName||'—') + '</h3><p class="text-sm text-gray-600">' + esc(a.email||'') + '</p>' +
    '<span class="inline-block mt-2 text-xs px-2.5 py-1 rounded-full ' + sc(a.applicationStatus) + '">' + esc(a.applicationStatus) + '</span></div></div>' +
    '<div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">' +
      '<div><span class="text-gray-500">Phone:</span> <strong>' + esc(a.contactNumber||'—') + '</strong></div>' +
      '<div><span class="text-gray-500">WhatsApp:</span> <strong>' + esc(a.whatsappContact||'—') + '</strong></div>' +
      '<div><span class="text-gray-500">Gender:</span> <strong>' + esc(a.gender||'—') + '</strong></div>' +
      '<div><span class="text-gray-500">Country:</span> <strong>' + esc(a.countryOfOrigin||'—') + '</strong></div>' +
      '<div class="sm:col-span-2"><span class="text-gray-500">Address:</span> <strong>' + esc(a.homeAddress||'—') + '</strong></div>' +
      '<div><span class="text-gray-500">Applying for:</span> <strong>' + esc(a.applyingFor||'—') + '</strong></div>' +
      '<div><span class="text-gray-500">Program type:</span> <strong>' + esc(a.programType||'—') + '</strong></div>' +
      '<div><span class="text-gray-500">Qualification:</span> <strong>' + esc(a.highestQualification||'—') + '</strong></div>' +
      '<div><span class="text-gray-500">Submitted:</span> <strong>' + (a.submittedAt ? esc(new Date(a.submittedAt).toLocaleString()) : '—') + '</strong></div>' +
    '</div>' +
    '<div><h4 class="font-semibold text-sm border-b-2 pb-1 mb-2" style="color:#0A4D68;border-color:#0A4D68">Programmes</h4><ol class="list-decimal list-inside text-sm">' + progs + '</ol></div>' +
    '<div><h4 class="font-semibold text-sm border-b-2 pb-1 mb-2" style="color:#0A4D68;border-color:#0A4D68">Grades</h4><div class="grid grid-cols-2 gap-1 text-sm">' + grades + '</div></div>' +
    '<div><h4 class="font-semibold text-sm border-b-2 pb-1 mb-2" style="color:#0A4D68;border-color:#0A4D68">Documents</h4>' + docs + '</div>' +
    '<div><h4 class="font-semibold text-sm border-b-2 pb-1 mb-2" style="color:#0A4D68;border-color:#0A4D68">Status</h4><div class="flex flex-wrap gap-2" id="status-btns">' + statuses + '</div></div>' +
    '<div><button type="button" id="btn-del-modal" class="bg-red-600 hover:bg-red-700 text-white text-sm font-semibold px-4 py-2 rounded-lg">Delete student</button></div>' +
  '</div>';
}

function renderChatTab(a) {
  return '<div class="p-4 flex flex-col" style="min-height:360px">' +
    '<div class="flex items-center gap-3 mb-3 pb-3 border-b">' +
      '<img src="' + STAFF + '" class="w-12 h-12 rounded-full object-cover border-2 border-teal-600"/>' +
      '<div><p class="font-semibold text-sm">Admissions Officer</p><p class="text-xs text-gray-500">Chat with ' + esc(a.fullName||'student') + '</p></div></div>' +
    '<div id="chat-msgs" class="flex-1 overflow-y-auto mb-3" style="max-height:280px"></div>' +
    '<div class="flex gap-2">' +
      '<input id="chat-input" type="text" placeholder="Type a message..." class="flex-1 border rounded-full px-4 py-2 text-sm outline-none"/>' +
      '<button type="button" id="chat-send" class="text-white px-4 py-2 rounded-full text-sm font-medium" style="background:#0A4D68">Send</button>' +
    '</div></div>';
}

function wireModal() {
  if (!selected) return;
  var bd = document.getElementById('modal-backdrop');
  var panel = document.getElementById('modal-panel');
  var close = document.getElementById('modal-close');
  if (bd) bd.onclick = function(e){ if (e.target === bd) { stopPoll(); selected = null; render(); } };
  if (panel) panel.onclick = function(e){ e.stopPropagation(); };
  if (close) close.onclick = function(){ stopPoll(); selected = null; render(); };
  document.querySelectorAll('[data-tab]').forEach(function(b){
    b.onclick = function(e){ e.stopPropagation(); setTab(b.getAttribute('data-tab')); };
  });
  document.querySelectorAll('[data-status]').forEach(function(b){
    b.onclick = function(e){ e.stopPropagation(); changeStatus(selected.userId, b.getAttribute('data-status')); };
  });
  var dm = document.getElementById('btn-del-modal');
  if (dm) dm.onclick = function(e){ e.stopPropagation(); deleteStudent(selected.userId, selected.fullName || selected.email); };
  var ci = document.getElementById('chat-input');
  var cs = document.getElementById('chat-send');
  if (ci) ci.onkeydown = function(e){ if (e.key === 'Enter') { chatText = ci.value; sendChat(); ci.value = ''; } };
  if (cs) cs.onclick = function(){ chatText = (ci && ci.value) || ''; sendChat(); if (ci) ci.value = ''; };
}

if (adminPwd) loadApps(); else render();
</script></body></html>`;




app.get('/', (req, res) => res.json({ success: true, message: 'AIT Admission API v4', admin: '/admin' }));
app.get('/admin', (req, res) => { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.send(ADMIN_HTML); });

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@')) return res.status(400).json({ success: false, message: 'Valid email required' });
    let user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      user = await User.create({
        email: email.toLowerCase().trim(), firstName: 'Applicant', lastName: 'New',
        contactNumber: '0000000000', gender: 'Male', dateOfBirth: new Date('2000-01-01'),
        whatsappContact: '0000000000', homeAddress: 'To be updated', countryOfOrigin: 'Ghana',
        applicationStatus: 'draft', currentStep: 1,
      });
      await Application.create({ user: user._id, programmeChoices: [], courseGrades: [], documents: [] });
    }
    res.json({
      success: true, token: generateToken(user._id.toString()),
      user: { id: user._id, email: user.email, firstName: user.firstName, middleName: user.middleName,
        lastName: user.lastName, photo: user.photo, currentStep: user.currentStep, applicationStatus: user.applicationStatus },
    });
  } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
});

app.get('/api/auth/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const application = await Application.findOne({ user: user._id });
    res.json({
      success: true,
      user: { id: user._id, email: user.email, firstName: user.firstName, middleName: user.middleName, lastName: user.lastName,
        photo: user.photo, contactNumber: user.contactNumber, otherContact: user.otherContact, gender: user.gender,
        dateOfBirth: user.dateOfBirth, whatsappContact: user.whatsappContact, homeAddress: user.homeAddress,
        countryOfOrigin: user.countryOfOrigin, currentStep: user.currentStep, applicationStatus: user.applicationStatus },
      application,
    });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
});

app.get('/api/application', protect, async (req, res) => {
  try {
    const application = await Application.findOne({ user: req.user._id });
    if (!application) return res.status(404).json({ success: false, message: 'Not found' });
    res.json({ success: true, application });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
});

app.put('/api/application/basic-info', protect, upload.single('photo'), async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const f = req.body;
    if (f.firstName) user.firstName = f.firstName;
    if (f.middleName !== undefined) user.middleName = f.middleName;
    if (f.lastName) user.lastName = f.lastName;
    if (f.contactNumber) user.contactNumber = f.contactNumber;
    if (f.otherContact !== undefined) user.otherContact = f.otherContact;
    if (f.gender) user.gender = f.gender;
    if (f.dateOfBirth) user.dateOfBirth = new Date(f.dateOfBirth);
    if (f.whatsappContact) user.whatsappContact = f.whatsappContact;
    if (f.homeAddress) user.homeAddress = f.homeAddress;
    if (f.countryOfOrigin) user.countryOfOrigin = f.countryOfOrigin;
    user.currentStep = Math.max(user.currentStep, 2);
    if (req.file) {
      if (user.photo) { const old = path.join(UPLOAD_DIR, path.basename(user.photo)); if (fs.existsSync(old)) fs.unlinkSync(old); }
      user.photo = `/uploads/${req.file.filename}`;
    }
    await user.save();
    res.json({ success: true, message: 'Updated', user: {
      id: user._id, email: user.email, firstName: user.firstName, middleName: user.middleName, lastName: user.lastName,
      photo: user.photo, contactNumber: user.contactNumber, otherContact: user.otherContact, gender: user.gender,
      dateOfBirth: user.dateOfBirth, whatsappContact: user.whatsappContact, homeAddress: user.homeAddress,
      countryOfOrigin: user.countryOfOrigin, currentStep: user.currentStep,
    }});
  } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
});

app.put('/api/application/programme-choices', protect, async (req, res) => {
  try {
    const { programmeChoices, applyingFor, programType } = req.body;
    if (!Array.isArray(programmeChoices) || programmeChoices.length < 1 || programmeChoices.length > 3)
      return res.status(400).json({ success: false, message: '1 to 3 choices required' });
    let application = await Application.findOne({ user: req.user._id });
    if (!application) application = await Application.create({ user: req.user._id });
    application.programmeChoices = programmeChoices.map((c, i) => ({ rank: i + 1, programme: c.programme, programmeCode: c.programmeCode || c.programme || '' }));
    if (applyingFor !== undefined) application.applyingFor = applyingFor;
    if (programType !== undefined) application.programType = programType;
    await application.save();
    const user = await User.findById(req.user._id);
    if (user) { user.currentStep = Math.max(user.currentStep, 3); await user.save(); }
    res.json({ success: true, application });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
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
    res.json({ success: true, application });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
});

app.post('/api/application/documents', protect, upload.array('documents', 10), async (req, res) => {
  try {
    if (!req.files || !req.files.length) return res.status(400).json({ success: false, message: 'No documents' });
    let application = await Application.findOne({ user: req.user._id });
    if (!application) application = await Application.create({ user: req.user._id });
    application.documents.push(...req.files.map(f => ({
      filename: f.filename, originalName: f.originalname, path: `/uploads/${f.filename}`,
      mimetype: f.mimetype, size: f.size, uploadedAt: new Date(),
    })));
    await application.save();
    const user = await User.findById(req.user._id);
    if (user) { user.currentStep = Math.max(user.currentStep, 5); await user.save(); }
    res.json({ success: true, documents: application.documents });
  } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Upload error' }); }
});

app.delete('/api/application/documents/:filename', protect, async (req, res) => {
  try {
    const application = await Application.findOne({ user: req.user._id });
    if (!application) return res.status(404).json({ success: false, message: 'Not found' });
    const doc = application.documents.find(d => d.filename === req.params.filename);
    if (!doc) return res.status(404).json({ success: false, message: 'Document not found' });
    const fp = path.join(UPLOAD_DIR, req.params.filename);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
    application.documents = application.documents.filter(d => d.filename !== req.params.filename);
    await application.save();
    res.json({ success: true, documents: application.documents });
  } catch (err) { res.status(500).json({ success: false, message: 'Delete error' }); }
});

app.post('/api/application/submit', protect, async (req, res) => {
  try {
    const application = await Application.findOne({ user: req.user._id });
    if (!application) return res.status(404).json({ success: false, message: 'Not found' });
    application.isComplete = true; application.submittedAt = new Date(); await application.save();
    const user = await User.findById(req.user._id);
    if (user) { user.applicationStatus = 'submitted'; user.currentStep = 6; await user.save(); }
    res.json({ success: true, message: 'Submitted', application });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
});

// ===== STUDENT CHAT =====
app.get('/api/chat', protect, async (req, res) => {
  try {
    const messages = await ChatMessage.find({ user: req.user._id }).sort({ createdAt: 1 }).limit(200);
    res.json({ success: true, messages });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
});
app.post('/api/chat', protect, async (req, res) => {
  try {
    const text = (req.body.text || '').trim();
    if (!text) return res.status(400).json({ success: false, message: 'Empty message' });
    const msg = await ChatMessage.create({ user: req.user._id, sender: 'student', text });
    res.json({ success: true, message: msg });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
});

// ===== ADMIN =====
app.post('/api/admin/login', (req, res) => {
  if ((req.body || {}).password === ADMIN_PASSWORD) return res.json({ success: true });
  return res.status(401).json({ success: false, message: 'Wrong password' });
});

app.get('/api/admin/applications', adminAuth, async (req, res) => {
  try {
    const applications = await Application.find().populate('user', '-password').sort({ updatedAt: -1 });
    const base = getBaseUrl(req);
    const result = applications.map(app => {
      const u = app.user || {};
      return {
        applicationId: app._id, userId: u._id, email: u.email,
        firstName: u.firstName, middleName: u.middleName, lastName: u.lastName,
        fullName: `${u.firstName || ''} ${u.middleName || ''} ${u.lastName || ''}`.replace(/\s+/g, ' ').trim(),
        photo: u.photo ? `${base}${u.photo}` : null,
        contactNumber: u.contactNumber, otherContact: u.otherContact, gender: u.gender,
        dateOfBirth: u.dateOfBirth, whatsappContact: u.whatsappContact, homeAddress: u.homeAddress,
        countryOfOrigin: u.countryOfOrigin, applicationStatus: u.applicationStatus, currentStep: u.currentStep,
        applyingFor: app.applyingFor, programType: app.programType,
        programmeChoices: app.programmeChoices, highestQualification: app.highestQualification,
        hasResults: app.hasResults, awaitingResults: app.awaitingResults, courseGrades: app.courseGrades,
        documents: (app.documents || []).map(d => { const o = d.toObject ? d.toObject() : d; return { ...o, url: `${base}${o.path}` }; }),
        isComplete: app.isComplete, submittedAt: app.submittedAt, createdAt: app.createdAt, updatedAt: app.updatedAt,
      };
    });
    res.json({ success: true, count: result.length, applications: result });
  } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
});

app.patch('/api/admin/applications/:userId/status', adminAuth, async (req, res) => {
  try {
    const allowed = ['draft', 'submitted', 'under_review', 'accepted', 'rejected'];
    if (!allowed.includes(req.body.status)) return res.status(400).json({ success: false, message: 'Invalid status' });
    const user = await User.findByIdAndUpdate(req.params.userId, { applicationStatus: req.body.status }, { new: true });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
});


app.delete('/api/admin/applications/:userId', adminAuth, async (req, res) => {
  try {
    const userId = req.params.userId;
    const application = await Application.findOne({ user: userId });
    if (application) {
      for (const d of (application.documents || [])) {
        if (d.filename) {
          const fp = path.join(UPLOAD_DIR, d.filename);
          if (fs.existsSync(fp)) fs.unlinkSync(fp);
        }
      }
      await Application.deleteOne({ _id: application._id });
    }
    const user = await User.findById(userId);
    if (user && user.photo) {
      const fp = path.join(UPLOAD_DIR, path.basename(user.photo));
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    await ChatMessage.deleteMany({ user: userId });
    await User.deleteOne({ _id: userId });
    res.json({ success: true, message: 'Student deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error deleting student' });
  }
});

app.get('/api/admin/chat/:userId', adminAuth, async (req, res) => {
  try {
    const messages = await ChatMessage.find({ user: req.params.userId }).sort({ createdAt: 1 }).limit(200);
    res.json({ success: true, messages });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
});
app.post('/api/admin/chat/:userId', adminAuth, async (req, res) => {
  try {
    const text = (req.body.text || '').trim();
    if (!text) return res.status(400).json({ success: false, message: 'Empty message' });
    const msg = await ChatMessage.create({ user: req.params.userId, sender: 'admin', text });
    res.json({ success: true, message: msg });
  } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ success: false, message: err.message || 'Internal Server Error' });
});
app.use((req, res) => res.status(404).json({ success: false, message: 'Route not found' }));

app.listen(PORT, () => {
  console.log(`🚀 AIT Backend v4 on port ${PORT}`);
  console.log(`🔐 Admin: /admin`);
});
