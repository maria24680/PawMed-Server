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