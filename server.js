// server.js
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- إعداد Express ---
const app = express();
const PORT = process.env.PORT || 5000;
// --- Middleware ---
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.use(express.static(path.join(__dirname, 'public')));


const SALT_ROUNDS = 10;

// تحميل بيانات المشرف من البيئة
const loadAdmins = () => {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;

  if (!username || !password) {
    console.error('❌ يجب تحديد ADMIN_USERNAME و ADMIN_PASSWORD في ملف .env');
    process.exit(1);
  }

  // تشفير كلمة المرور عند التشغيل
  const hashedPassword = bcrypt.hashSync(password, SALT_ROUNDS);

  // إرجاع مصفوفة تحتوي على المشرف (في الذاكرة فقط)
  return [
    {
      id: 1,
      username,
      password: hashedPassword
    }
  ];
};

// تحميل المشرفين إلى الذاكرة
let admins = loadAdmins();

// --- نقطة نهاية تسجيل الدخول ---
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  const admin = admins.find(a => a.username === username);
  if (!admin) {
    return res.status(401).json({ error: 'Falscher Benutzername oder falsches Passwort' });
  }

  const isMatch = await bcrypt.compare(password, admin.password);
  if (!isMatch) {
    return res.status(401).json({ error: 'Falscher Benutzername oder falsches Passwort' });
  }

  // نعود برمز مصادقة بسيط (يمكنك استخدام JWT لاحقًا)
  res.json({ success: true, token: 'admin-auth-token-2025' });
});

// --- إعداد قاعدة البيانات ---

// --- تعريف Schema و Model ---
const medicalRecordSchema = new mongoose.Schema({
  servicecode: { type: String, required: true },
  idNumber: { type: String, required: true },
  name: { type: String, required: true },
  issueDate: { type: Date, required: true },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  duration: { type: Number, required: true },
  doctor: { type: String, required: true },
  jobTitle: { type: String, required: true }
}, {
  timestamps: true
});

const MedicalRecord = mongoose.model('MedicalRecord', medicalRecordSchema);




// GET /api/medical — جلب جميع السجلات
app.get('/api/medical', async (req, res) => {
  try {
    const records = await MedicalRecord.find().sort({ createdAt: -1 }); // الأحدث أولًا
    res.json(records);
  } catch (error) {
    console.error('خطأ في جلب السجلات:', error);
    res.status(500).json({ error: 'فشل جلب السجلات' });
  }
});

// --- المسارات (Routes) ---
app.post('/api/medical', async (req, res) => {
  try {
    const record = new MedicalRecord(req.body);
    await record.save();
    res.status(201).json({ message: 'تم حفظ البيانات بنجاح!', id: record._id });
  } catch (error) {
    console.error('خطأ في الحفظ:', error);
    res.status(400).json({ error: error.message || 'فشل حفظ البيانات' });
  }
});
// --- مسار آمن للبحث عن سجل طبي باستخدام idNumber و servicecode ---
app.get('/api/medical/search', async (req, res) => {
  const { idNumber, servicecode } = req.query;

  // 1. التحقق من وجود المُعطيات
  if (!idNumber || !servicecode) {
    return res.status(400).json({ error: 'الرجاء إدخال رقم الهوية ورمز الخدمة' });
  }

  // 2. التحقق من أن المُعطيات سلاسل نصية (لمنع حقن كائنات)
  if (typeof idNumber !== 'string' || typeof servicecode !== 'string') {
    return res.status(400).json({ error: 'بيانات الإدخال غير صالحة' });
  }

  // 3. تنقية المدخلات من أي أحرف غير مرغوب فيها (حماية إضافية)
  const cleanIdNumber = idNumber.trim();
  const cleanServiceCode = servicecode.trim();

  // 4. التحقق من التنسيق باستخدام تعبيرات منتظمة
  const idRegex = /^\d{10}$/; // رقم هوية/إقامة سعودي: 10 أرقام فقط
  const serviceCodeRegex = /^[A-Za-z0-9]{6,20}$/; // أحرف وأرقام، طول 6–20

  if (!idRegex.test(cleanIdNumber)) {
    return res.status(400).json({ error: 'رقم الهوية أو الإقامة غير صحيح' });
  }

  if (!serviceCodeRegex.test(cleanServiceCode)) {
    return res.status(400).json({ error: 'رمز الخدمة غير صحيح' });
  }

  try {
    // 5. منع حقن NoSQL: نضمن أن القيم نصوص بسيطة (تم بالفعل أعلاه)
    const record = await MedicalRecord.findOne(
      {
        idNumber: cleanIdNumber,
        servicecode: cleanServiceCode
      },
      {
        // 6. عرض الحقول المطلوبة فقط (عدم تسريب _id أو __v أو أي حقول داخلية)
        _id: 0,
        __v: 0,
      }
    ).lean();

    if (!record) {
      // 7. رسالة خطأ عامة (لا تكشف عن وجود/عدم وجود سجل)
      return res.status(404).json({ error: 'خطا في الاستعلام' });
    }

    // 👇👇 الإضافة الأساسية: منع فهرسة نتائج الاستعلام من قبل محركات البحث 👇👇
    res.set('X-Robots-Tag', 'noindex, nofollow, nosnippet, noarchive');

    // 8. التأكد من أن القيم آمنة للعرض
    const safeResponse = {
      name: typeof record.name === 'string' ? record.name : '',
      issueDate: record.issueDate instanceof Date ? record.issueDate.toISOString() : record.issueDate,
      startDate: record.startDate instanceof Date ? record.startDate.toISOString() : record.startDate,
      endDate: record.endDate instanceof Date ? record.endDate.toISOString() : record.endDate,
      duration: typeof record.duration === 'number' ? record.duration : 0,
      doctor: typeof record.doctor === 'string' ? record.doctor : '',
      jobTitle: typeof record.jobTitle === 'string' ? record.jobTitle : ''
    };

    res.json(safeResponse);
  } catch (error) {
    console.error('خطأ أمني محتمل أو فني:', error);
    // 9. رسالة خطأ عامة — لا تكشف عن التفاصيل الداخلية
    res.status(500).json({ error: 'تعذر معالجة الطلب' });
  }
});

// DELETE /api/medical/:id
app.delete('/api/medical/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await MedicalRecord.findByIdAndDelete(id);

    if (!deleted) {
      return res.status(404).json({ error: 'السجل غير موجود' });
    }

    res.json({ message: 'تم الحذف بنجاح' });
  } catch (error) {
    console.error('خطأ في الحذف:', error);
    res.status(500).json({ error: 'فشل الحذف' });
  }
});

// PUT /api/medical/:id
app.put('/api/medical/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updatedRecord = await MedicalRecord.findByIdAndUpdate(
      id,
      req.body,
      { new: true, runValidators: true } // يعيد القيمة المحدثة ويتحقق من الـ schema
    );

    if (!updatedRecord) {
      return res.status(404).json({ error: 'السجل غير موجود' });
    }

    res.json(updatedRecord);
  } catch (error) {
    console.error('خطأ في التعديل:', error);
    res.status(400).json({ error: error.message || 'فشل تحديث السجل' });
  }
});

// GET /api/medical/:id
app.get('/api/medical/:id', async (req, res) => {
  try {
    const record = await MedicalRecord.findById(req.params.id);
    if (!record) {
      return res.status(404).json({ error: 'السجل غير موجود' });
    }
    res.json(record);
  } catch (error) {
    res.status(500).json({ error: 'خطأ في جلب السجل' });
  }
});



app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- الاتصال بـ MongoDB وتشغيل الخادم ---
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('✅ تم الاتصال بقاعدة بيانات MongoDB');
    app.listen(PORT, () => {
      console.log(`🚀 الخادم يعمل على http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('❌ فشل الاتصال بـ MongoDB:', err);
    process.exit(1);
  });
