import express, { Express, Request, Response, NextFunction } from 'express';
import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';

dotenv.config();

const app: Express = express();
const PORT = process.env.PORT || 8000;

// ============================================
// MIDDLEWARE
// ============================================

app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3
    001', 'http://localhost:3002'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ============================================
// MONGODB CONNECTION
// ============================================

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/pawmed');
    console.log('✅ MongoDB Connected to pawmed database');
  } catch (error: any) {
    console.error('❌ MongoDB Error:', error.message);
    process.exit(1);
  }
};

// ============================================
// USER SCHEMA & MODEL
// ============================================

interface IUser extends Document {
  name: string;
  email: string;
  password: string;
  role: 'admin' | 'veterinarian' | 'client';
  phone: string;
  address?: string;
  profileImage?: string;
  specialization?: string[];
  licenseNumber?: string;
  experience?: number;
  isActive: boolean;
  emailVerified: boolean;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const UserSchema = new Schema<IUser>({
  name: { type: String, required: [true, 'Please provide a name'], trim: true },
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    lowercase: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  role: {
    type: String,
    enum: ['admin', 'veterinarian', 'client'],
    default: 'client'
  },
  phone: { type: String, required: [true, 'Please provide a phone number'], trim: true },
  address: { type: String, trim: true },
  profileImage: { type: String, default: 'https://ui-avatars.com/api/?background=random&name=User' },
  specialization: { type: [String], default: [] },
  licenseNumber: { type: String, sparse: true },
  experience: { type: Number, min: 0 },
  isActive: { type: Boolean, default: true },
  emailVerified: { type: Boolean, default: false }
}, { timestamps: true });

UserSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

UserSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model<IUser>('User', UserSchema);

// ============================================
// PET SCHEMA & MODEL
// ============================================

interface IPet extends Document {
  name: string;
  species: string;
  breed: string;
  dateOfBirth: Date;
  gender: 'male' | 'female' | 'neutered' | 'spayed';
  weight: number;
  weightUnit: 'kg' | 'lbs';
  color: string;
  microchipId?: string;
  owner: mongoose.Types.ObjectId;
  medicalHistory: any[];
  allergies: string[];
  chronicConditions: string[];
  currentMedications: any[];
  vaccinationHistory: any[];
  isActive: boolean;
  lastVisit?: Date;
  profileImage?: string;
}

const PetSchema = new Schema<IPet>({
  name: { type: String, required: [true, 'Please provide pet name'], trim: true },
  species: {
    type: String,
    required: [true, 'Please provide species'],
    enum: ['Dog', 'Cat', 'Bird', 'Rabbit', 'Hamster', 'Fish', 'Reptile', 'Other']
  },
  breed: { type: String, required: [true, 'Please provide breed'], trim: true },
  dateOfBirth: { type: Date, required: [true, 'Please provide date of birth'] },
  gender: {
    type: String,
    enum: ['male', 'female', 'neutered', 'spayed'],
    required: true
  },
  weight: { type: Number, required: [true, 'Please provide weight'], min: 0 },
  weightUnit: { type: String, enum: ['kg', 'lbs'], default: 'kg' },
  color: { type: String, required: [true, 'Please provide color'], trim: true },
  microchipId: { type: String, sparse: true, trim: true },
  owner: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  medicalHistory: [
    {
      date: { type: Date, required: true },
      condition: { type: String, required: true },
      diagnosis: { type: String, required: true },
      treatment: { type: String, required: true },
      veterinarian: { type: Schema.Types.ObjectId, ref: 'User', required: true },
      notes: String
    }
  ],
  allergies: [String],
  chronicConditions: [String],
  currentMedications: [
    {
      name: { type: String, required: true },
      dosage: { type: String, required: true },
      frequency: { type: String, required: true },
      startDate: { type: Date, required: true },
      endDate: Date,
      isActive: { type: Boolean, default: true }
    }
  ],
  vaccinationHistory: [
    {
      name: { type: String, required: true },
      date: { type: Date, required: true },
      expiryDate: { type: Date, required: true },
      veterinarian: { type: Schema.Types.ObjectId, ref: 'User', required: true },
      batchNumber: String
    }
  ],
  isActive: { type: Boolean, default: true },
  lastVisit: Date,
  profileImage: { type: String, default: 'https://ui-avatars.com/api/?background=random&name=Pet' }
}, { timestamps: true });

const Pet = mongoose.model<IPet>('Pet', PetSchema);

// ============================================
// APPOINTMENT SCHEMA & MODEL
// ============================================

interface IAppointment extends Document {
  client: mongoose.Types.ObjectId;
  pet: mongoose.Types.ObjectId;
  veterinarian: mongoose.Types.ObjectId;
  appointmentType: 'checkup' | 'vaccination' | 'surgery' | 'dental' | 'emergency' | 'followup' | 'consultation';
  date: Date;
  time: string;
  duration: number;
  status: 'scheduled' | 'confirmed' | 'in-progress' | 'completed' | 'cancelled' | 'no-show';
  symptoms?: string[];
  priority: 'low' | 'normal' | 'high' | 'emergency';
  notes?: string;
  paymentStatus: 'pending' | 'paid' | 'insurance' | 'refunded';
  paymentId?: string;
  amount?: number;
  reminderSent: boolean;
}

const AppointmentSchema = new Schema<IAppointment>({
  client: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  pet: { type: Schema.Types.ObjectId, ref: 'Pet', required: true },
  veterinarian: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  appointmentType: {
    type: String,
    enum: ['checkup', 'vaccination', 'surgery', 'dental', 'emergency', 'followup', 'consultation'],
    required: true
  },
  date: { type: Date, required: true },
  time: { type: String, required: true },
  duration: { type: Number, default: 30 },
  status: {
    type: String,
    enum: ['scheduled', 'confirmed', 'in-progress', 'completed', 'cancelled', 'no-show'],
    default: 'scheduled'
  },
  symptoms: [String],
  priority: { type: String, enum: ['low', 'normal', 'high', 'emergency'], default: 'normal' },
  notes: String,
  paymentStatus: {
    type: String,
    enum: ['pending', 'paid', 'insurance', 'refunded'],
    default: 'pending'
  },
  paymentId: String,
  amount: { type: Number, min: 0 },
  reminderSent: { type: Boolean, default: false }
}, { timestamps: true });

const Appointment = mongoose.model<IAppointment>('Appointment', AppointmentSchema);

// ============================================
// SERVICE SCHEMA & MODEL
// ============================================

interface IService extends Document {
  name: string;
  description: string;
  category: 'consultation' | 'vaccination' | 'surgery' | 'dental' | 'diagnostic' | 'emergency' | 'wellness' | 'specialist';
  price: number;
  duration: number;
  isAvailable: boolean;
  requiresSpecialist: boolean;
  preparationInstructions?: string;
  aftercareInstructions?: string;
  image?: string;
}

const ServiceSchema = new Schema<IService>({
  name: { type: String, required: [true, 'Please provide service name'], trim: true },
  description: { type: String, required: [true, 'Please provide description'] },
  category: {
    type: String,
    enum: ['consultation', 'vaccination', 'surgery', 'dental', 'diagnostic', 'emergency', 'wellness', 'specialist'],
    required: true
  },
  price: { type: Number, required: [true, 'Please provide price'], min: 0 },
  duration: { type: Number, required: [true, 'Please provide duration in minutes'], min: 10 },
  isAvailable: { type: Boolean, default: true },
  requiresSpecialist: { type: Boolean, default: false },
  preparationInstructions: String,
  aftercareInstructions: String,
  image: { type: String, default: 'https://via.placeholder.com/300x200?text=Service' }
}, { timestamps: true });

const Service = mongoose.model<IService>('Service', ServiceSchema);

// ============================================
// PRESCRIPTION SCHEMA & MODEL
// ============================================

interface IPrescription extends Document {
  pet: mongoose.Types.ObjectId;
  veterinarian: mongoose.Types.ObjectId;
  client: mongoose.Types.ObjectId;
  medications: {
    name: string;
    dosage: string;
    frequency: string;
    duration: string;
    quantity: number;
    refills: number;
    route: 'oral' | 'topical' | 'injection' | 'intravenous' | 'subcutaneous';
    instructions?: string;
  }[];
  diagnosis: string;
  notes?: string;
  issuedDate: Date;
  validUntil: Date;
  isActive: boolean;
  isRefillable: boolean;
  refillsRemaining: number;
}

const PrescriptionSchema = new Schema<IPrescription>({
  pet: { type: Schema.Types.ObjectId, ref: 'Pet', required: true },
  veterinarian: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  client: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  medications: [
    {
      name: { type: String, required: true },
      dosage: { type: String, required: true },
      frequency: { type: String, required: true },
      duration: { type: String, required: true },
      quantity: { type: Number, required: true, min: 1 },
      refills: { type: Number, default: 0 },
      route: {
        type: String,
        enum: ['oral', 'topical', 'injection', 'intravenous', 'subcutaneous'],
        required: true
      },
      instructions: String
    }
  ],
  diagnosis: { type: String, required: true },
  notes: String,
  issuedDate: { type: Date, default: Date.now },
  validUntil: { type: Date, required: true },
  isActive: { type: Boolean, default: true },
  isRefillable: { type: Boolean, default: false },
  refillsRemaining: { type: Number, default: 0 }
}, { timestamps: true });

const Prescription = mongoose.model<IPrescription>('Prescription', PrescriptionSchema);

// ============================================
// PAYMENT SCHEMA & MODEL
// ============================================

interface IPayment extends Document {
  appointment: mongoose.Types.ObjectId;
  user: mongoose.Types.ObjectId;
  amount: number;
  currency: string;
  stripePaymentId: string;
  status: 'pending' | 'succeeded' | 'failed' | 'refunded';
  paymentMethod: string;
  receiptUrl?: string;
  metadata?: Record<string, any>;
}

const PaymentSchema = new Schema<IPayment>({
  appointment: { type: Schema.Types.ObjectId, ref: 'Appointment', required: true },
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true, min: 0 },
  currency: { type: String, default: 'usd' },
  stripePaymentId: { type: String, required: true, unique: true },
  status: {
    type: String,
    enum: ['pending', 'succeeded', 'failed', 'refunded'],
    default: 'pending'
  },
  paymentMethod: { type: String, required: true },
  receiptUrl: String,
  metadata: Schema.Types.Mixed
}, { timestamps: true });

const Payment = mongoose.model<IPayment>('Payment', PaymentSchema);

// ============================================
// MEDICAL RECORD SCHEMA & MODEL
// ============================================

interface IMedicalRecord extends Document {
  pet: mongoose.Types.ObjectId;
  veterinarian: mongoose.Types.ObjectId;
  appointment: mongoose.Types.ObjectId;
  visitDate: Date;
  chiefComplaint: string;
  history: string;
  clinicalFindings: string;
  diagnosis: string;
  treatment: string;
  medications: {
    name: string;
    dosage: string;
    frequency: string;
    duration: string;
    route: 'oral' | 'topical' | 'injection' | 'intravenous' | 'subcutaneous';
    prescribedBy: mongoose.Types.ObjectId;
  }[];
  labResults?: string[];
  imagingResults?: string[];
  followUpInstructions?: string;
  followUpDate?: Date;
  isEmergency: boolean;
  status: 'active' | 'resolved' | 'chronic';
  notes?: string;
}

const MedicalRecordSchema = new Schema<IMedicalRecord>({
  pet: { type: Schema.Types.ObjectId, ref: 'Pet', required: true },
  veterinarian: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  appointment: { type: Schema.Types.ObjectId, ref: 'Appointment', required: true },
  visitDate: { type: Date, required: true, default: Date.now },
  chiefComplaint: { type: String, required: [true, 'Please provide chief complaint'] },
  history: { type: String, required: [true, 'Please provide medical history'] },
  clinicalFindings: { type: String, required: [true, 'Please provide clinical findings'] },
  diagnosis: { type: String, required: [true, 'Please provide diagnosis'] },
  treatment: { type: String, required: [true, 'Please provide treatment plan'] },
  medications: [
    {
      name: { type: String, required: true },
      dosage: { type: String, required: true },
      frequency: { type: String, required: true },
      duration: { type: String, required: true },
      route: {
        type: String,
        enum: ['oral', 'topical', 'injection', 'intravenous', 'subcutaneous'],
        required: true
      },
      prescribedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true }
    }
  ],
  labResults: [String],
  imagingResults: [String],
  followUpInstructions: String,
  followUpDate: Date,
  isEmergency: { type: Boolean, default: false },
  status: { type: String, enum: ['active', 'resolved', 'chronic'], default: 'active' },
  notes: String
}, { timestamps: true });
const MedicalRecord = mongoose.model<IMedicalRecord>('MedicalRecord', MedicalRecordSchema);

// ============================================
// AUTH MIDDLEWARE
// ============================================

interface AuthRequest extends Request {
  user?: IUser;
  token?: string;
}

const auth = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      res.status(401).json({ message: 'No token, authorization denied' });
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret') as { id: string };
    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      res.status(401).json({ message: 'Token is not valid' });
      return;
    }

    if (!user.isActive) {
      res.status(401).json({ message: 'User account is deactivated' });
      return;
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

const roleCheck = (...roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ message: 'User not authenticated' });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({
        message: `Role ${req.user.role} is not authorized to access this resource`
      });
      return;
    }

    next();
  };
};

// ============================================
// UTILITY FUNCTIONS
// ============================================

const generateToken = (user: IUser): string => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    process.env.JWT_SECRET || 'secret',
    { expiresIn: '7d' }
  );
};

// ============================================
// ROOT ROUTE (✅ FIX: prevents 404 on GET /)
// ============================================

app.get('/', (req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: '🏥 Welcome to PawMed Veterinary Clinic API',
    docs: {
      health: '/api/health',
      login: '/api/auth/login',
      register: '/api/auth/register',
      issueToken: '/api/auth/issue-token',
      pets: '/api/pets',
      appointments: '/api/appointments',
      services: '/api/services',
      prescriptions: '/api/prescriptions',
      payments: '/api/payments',
      medicalRecords: '/api/medicalrecords',
      adminDashboard: '/api/admin/dashboard'
    }
  });
});

// ============================================
// AUTH ROUTES
// ============================================

// Register
app.post('/api/auth/register', async (req: Request, res: Response) => {
  try {
    const { name, email, password, phone, address } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const user = await User.create({
      name,
      email,
      password,
      phone,
      address,
      role: 'client'
    });

    const token = generateToken(user);
    const userData = user.toObject() as Partial<IUser>;
    delete userData.password;

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: { user: userData, token }
    });
  } catch (error: any) {
    console.error('Register Error:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  }
});

// Login
app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordMatch = await user.comparePassword(password);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.status(401).json({ message: 'Account is deactivated' });
    }

    const token = generateToken(user);
    const userData = user.toObject() as Partial<IUser>;
    delete userData.password;

    return res.status(200).json({
      success: true,
      message: 'Login successful',
      data: { user: userData, token }
    });
  } catch (error: any) {
    console.error('Login Error:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  }
});

// ============================================
// INTERNAL BRIDGE ROUTE (better-auth -> Express JWT)
// ============================================
//
// This lets the Next.js server (which owns the better-auth session/cookie)
// exchange a verified user email for a real JWT that this Express backend's
// `auth` middleware understands. It is NOT meant to be called from the
// browser — only from your Next.js server-side route, using a shared
// secret that never reaches client code.
//
// SECURITY NOTES:
// - INTERNAL_API_SECRET must be a long random value, set in both the
//   Express .env and the Next.js server .env (no NEXT_PUBLIC_ prefix there).
// - This route deliberately does NOT take a password — the caller has
//   already proven identity via better-auth's own session verification.
//   Do not relax the secret check "just for testing"; anyone who can hit
//   this endpoint with a valid secret can mint a token for any email.

const INTERNAL_API_SECRET = process.env.INTERNAL_API_SECRET || '';

if (!INTERNAL_API_SECRET && process.env.NODE_ENV !== 'test') {
  console.warn('⚠️  INTERNAL_API_SECRET is not set. /api/auth/issue-token is effectively unprotected until you set it.');
}

app.post('/api/auth/issue-token', async (req: Request, res: Response) => {
  try {
    const providedSecret = req.header('x-internal-secret');

    if (!INTERNAL_API_SECRET || providedSecret !== INTERNAL_API_SECRET) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const { email } = req.body;
    if (!email || typeof email !== 'string') {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (!user.isActive) {
      return res.status(401).json({ success: false, message: 'User account is deactivated' });
    }

    const token = generateToken(user);
    const userData = user.toObject() as Partial<IUser>;
    delete userData.password;

    return res.status(200).json({
      success: true,
      data: { token, user: userData }
    });
  } catch (error: any) {
    console.error('Issue Token Error:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  }
});

// Get current user
app.get('/api/auth/me', auth, async (req: AuthRequest, res: Response) => {
  try {
    const user = await User.findById(req.user?._id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userData = user.toObject() as Partial<IUser>;
    delete userData.password;

    return res.status(200).json({
      success: true,
      data: { user: userData }
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  }
});

// Update profile
app.put('/api/auth/profile', auth, async (req: AuthRequest, res: Response) => {
  try {
    const { name, phone, address, profileImage } = req.body;
    const userId = req.user?._id;

    const user = await User.findByIdAndUpdate(
      userId,
      { name, phone, address, profileImage },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userData = user.toObject() as Partial<IUser>;
    delete userData.password;

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: { user: userData }
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  }
});

// ============================================
// PET ROUTES
// ============================================

// Create pet
app.post('/api/pets', auth, async (req: AuthRequest, res: Response) => {
  try {
    const petData = { ...req.body, owner: req.user?._id };
    const pet = await Pet.create(petData);
    return res.status(201).json({
      success: true,
      message: 'Pet created successfully',
      data: { pet }
    });
  } catch (error: any) {
    console.error('Pet Creation Error:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  }
});

// Get all pets
app.get('/api/pets', auth, async (req: AuthRequest, res: Response) => {
  try {
    const { search = '', species } = req.query;
    const query: any = {};

    if (req.user?.role === 'client') {
      query.owner = req.user._id;
    }

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { species: { $regex: search, $options: 'i' } },
        { breed: { $regex: search, $options: 'i' } }
      ];
    }

    if (species) query.species = species;

    const pets = await Pet.find(query)
      .populate('owner', 'name email phone')
      .sort({ createdAt: -1 });

    return res.status(200).json({
      success: true,
      data: { pets }
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  }
});

// Get pet by ID
app.get('/api/pets/:id', auth, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const pet = await Pet.findById(id)
      .populate('owner', 'name email phone address')
      .populate('medicalHistory.veterinarian', 'name specialization')
      .populate('vaccinationHistory.veterinarian', 'name specialization');

    if (!pet) {
      return res.status(404).json({ message: 'Pet not found' });
    }

    return res.status(200).json({
      success: true,
      data: { pet }
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  }
});

// Update pet
app.put('/api/pets/:id', auth, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const pet = await Pet.findByIdAndUpdate(id, req.body, { new: true, runValidators: true });

    if (!pet) {
      return res.status(404).json({ message: 'Pet not found' });
    }

    return res.status(200).json({
      success: true,
      message: 'Pet updated successfully',
      data: { pet }
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  }
});

// Delete pet
app.delete('/api/pets/:id', auth, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const pet = await Pet.findByIdAndDelete(id);

    if (!pet) {
      return res.status(404).json({ message: 'Pet not found' });
    }

    return res.status(200).json({
      success: true,
      message: 'Pet deleted successfully'
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      message: error.message || 'Server Error'
    });
  }
});