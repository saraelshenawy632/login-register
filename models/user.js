import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address']
    },
    password: {
        type: String,
        required: true,
        select: false // 🛡️ يحمي الباسورد من الرجوع في الاستعلامات
    },
    firstName: { // تأكد من أن الاسم مكتوب بحرف صغير
        type: String,
        required: true,
        trim: true
    },
    lastName: {
        type: String,
        required: true,
        trim: true
    },
    phoneNumber: {
        type: String,
        required: true,
        match: [/^\d{11}$/, 'Phone number should be 11 digits']
    },
    address: {
        type: String,
        required: true,
        trim: true
    },
    role: {
        type: String,
        required: true,
        enum: ['user', 'admin'],
        default: 'user'
    }
}, { timestamps: true });

// 📌 دالة تحديث بيانات المستخدم
userSchema.statics.updateUser = async function (id, updateData) {
    try {
        // التحقق من وجود المستخدم
        const user = await this.findById(id);
        if (!user) {
            throw new Error('❌ المستخدم غير موجود.');
        }

        // إذا كان هناك كلمة مرور جديدة، يتم تشفيرها
        if (updateData.password) {
            updateData.password = await bcrypt.hash(updateData.password, 10);
        } else {
            delete updateData.password; // ⚠️ لا يتم تغيير كلمة المرور إذا لم يتم إرسالها
        }

        // تحديث بيانات المستخدم
        const updatedUser = await this.findByIdAndUpdate(id, updateData, { new: true, runValidators: true });

        return updatedUser;
    } catch (error) {
        throw new Error(`❌ خطأ أثناء تحديث البيانات: ${error.message}`);
    }
};

const User = mongoose.model('User', userSchema);

export default User;
