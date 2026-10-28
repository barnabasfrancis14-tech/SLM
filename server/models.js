import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
  passwordHash: {
  type: String,
  required: false,
  select: false
},
googleId: {
  type: String,
  unique: true,
  sparse: true,
  index: true
},
  college: { type: String, default: '', maxlength: 180 },
  course: { type: String, default: '', maxlength: 100 },
  department: { type: String, default: '', maxlength: 120 },
  year: { type: String, default: '', maxlength: 40 },
  photo: { type: String, default: '', maxlength: 250000 },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true, strict: true });

const studentDataSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
  theme: { type: String, enum: ['light', 'dark'], default: 'light' },
  tasks: { type: [mongoose.Schema.Types.Mixed], default: [] },
  assignments: { type: [mongoose.Schema.Types.Mixed], default: [] },
  exams: { type: [mongoose.Schema.Types.Mixed], default: [] },
  timetable: { type: [mongoose.Schema.Types.Mixed], default: [] },
  attendance: { type: [mongoose.Schema.Types.Mixed], default: [] },
  expenses: { type: [mongoose.Schema.Types.Mixed], default: [] },
  goals: { type: [mongoose.Schema.Types.Mixed], default: [] },
  notes: { type: [mongoose.Schema.Types.Mixed], default: [] },
  settings: { type: mongoose.Schema.Types.Mixed, default: { emailReminders: false, reminderWindow: '1' } },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true, strict: true });

export const User = mongoose.model('User', userSchema);
export const StudentData = mongoose.model('StudentData', studentDataSchema);
