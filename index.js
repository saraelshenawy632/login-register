import bcrypt from 'bcrypt';
import express from 'express';
import session from 'express-session';
import { engine } from 'express-handlebars';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
import MongoStore from 'connect-mongo'; 
import dotenv from 'dotenv';
import User from './models/user.js';

// إعداد المسارات
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.resolve(__dirname, '../.env/secret.env') }); // تحميل المتغيرات من .env

const app = express();
const port = process.env.PORT || 3000;

// إعداد Handlebars
app.engine('hbs', engine({
    extname: '.hbs',
    defaultLayout: 'main',
    layoutsDir: path.join(__dirname, 'templates', 'layouts'),
    helpers: {
        increment: function (value) {
            return parseInt(value) + 1;
        }
    },
    runtimeOptions: {
        allowProtoPropertiesByDefault: true,
        allowProtoMethodsByDefault: true
    }
}));
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'templates'));

// إعداد الملفات الثابتة
app.use(express.static(path.join(__dirname, '../public')));

// إعداد body parser لاستقبال البيانات من الفورم
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// الاتصال بقاعدة البيانات
async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 50000 // زيادة مهلة الاتصال إلى 50 ثانية
        });
        console.log('✅ Connected to MongoDB');
    } catch (err) {
        console.error('❌ Error connecting to MongoDB:', err);
    }
}
connectDB();

// إعداد الجلسة باستخدام MongoStore
app.use(session({
    secret: process.env.SESSION_SECRET, // اجعليه في env للحماية
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        ttl: 14 * 24 * 60 * 60 // 14 days
    }),
    cookie: { maxAge: 1000 * 60 * 60 * 2 } // الجلسة صالحة لساعتين
}));

// Middleware لحماية الصفحات الخاصة
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Middleware للتحقق من صلاحيات المسؤول
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ message: '❌ Access denied! Admins only.' });
}

// ========== ROUTES ==========

// الصفحة الرئيسية
app.get('/', (req, res) => {
    res.render('home', { 
        title: 'Home', 
        isLoggedIn: !!req.session.user 
    });
});

// صفحة التسجيل
app.get('/register', (req, res) => {
    res.render('register', { title: 'Register' });
});

// عملية التسجيل
app.post('/register', async (req, res) => {
    try {
        console.log('Received data:', req.body); // عرض البيانات المستلمة من النموذج

        const { firstName, lastName, phoneNumber, address, role, email, password } = req.body;

        if (!firstName || !lastName || !phoneNumber || !address || !role || !email || !password) {
            return res.status(400).json({ message: '⚠️ All fields are required!' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: '⚠️ Email already registered!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            firstName,
            lastName,
            phoneNumber,
            address,
            role,
            email,
            password: hashedPassword
        });

        await newUser.save();

        req.session.user = { 
            id: newUser._id, 
            email: newUser.email,
            firstName: newUser.firstName, 
            lastName: newUser.lastName, 
            role: newUser.role 
        };

        res.status(201).json({ message: '✅ Registration successful!' });
    } catch (error) {
        console.error('❌ Error during registration:', error);
        res.status(500).json({ message: '❌ Server error during registration.' });
    }
});

// صفحة الدخول
app.get('/login', (req, res) => {
    res.render('login', { title: 'Login' });
});

// عملية الدخول
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email }).select('+password');
        if (!user) {
            return res.status(404).json({ message: 'User not found!' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Incorrect password!' });
        }

        // حفظ البيانات في الجلسة
        req.session.user = { 
            id: user._id, 
            email: user.email,
            firstName: user.firstName, 
            lastName: user.lastName, 
            role: user.role 
        };

        res.json({ message: 'Login successful!' });
    } catch (error) {
        console.error('❌ Error during login:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// صفحة Dashboard
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', {
        title: 'Dashboard',
        userEmail: req.session.user.email,
        userId: req.session.user.id,
        userFirstName: req.session.user.firstName,
        userLastName: req.session.user.lastName,
        isAdmin: req.session.user.role === 'admin'
    });
});

// عرض جميع المستخدمين (للمسؤولين فقط)
app.get('/admin/users', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const users = await User.find({}, '-password'); // ⚠️ تأكد من أن الحقول موجودة في قاعدة البيانات
        res.render('admin-users', { 
            title: 'All Users', 
            users 
        });
    } catch (error) {
        console.error('❌ Error fetching users:', error);
        res.status(500).json({ message: '❌ Server error while fetching users.' });
    }
});

// تحديث بيانات المستخدم
app.post('/update', async (req, res) => {
    try {
        const { id, firstName, lastName, phoneNumber, address, role, email, password } = req.body;

        console.log('Received update request:', req.body);

        // التحقق من وجود المستخدم
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ message: '❌ المستخدم غير موجود.' });
        }

        // تجهيز البيانات المراد تحديثها
        const updateData = { firstName, lastName, phoneNumber, address, role, email };

        // تحديث كلمة المرور إذا تم إرسالها
        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }

        // تحديث المستخدم بدون إنشاء مستخدم جديد
        const updatedUser = await User.findByIdAndUpdate(id, updateData, { new: true, upsert: false });

        // إذا كان المستخدم الذي يتم تحديثه هو المستخدم الحالي، قم بتحديث الجلسة
        if (req.session.user.id === id) {
            req.session.user.role = updatedUser.role; // تحديث الدور في الجلسة
        }

        res.status(200).json({ message: '✅ تم تحديث البيانات بنجاح!', user: updatedUser });
    } catch (error) {
        console.error('❌ خطأ أثناء تحديث البيانات:', error);
        res.status(500).json({ message: '❌ خطأ في الخادم أثناء تحديث البيانات.' });
    }
});

// تسجيل الخروج
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('❌ Error during logout:', err);
            res.redirect('/dashboard');
        } else {
            res.clearCookie('connect.sid');
            res.redirect('/login');
        }
    });
});

// تشغيل السيرفر
app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});

export default app;
