import express, { Express, Request, Response, NextFunction } from 'express';
import { MongoClient, Db, Collection, ObjectId, Filter, Document as MongoDoc } from 'mongodb';
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
  origin: [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:3002',
    // Add your deployed Next.js frontend's real origin(s) here, e.g.:
    // 'https://pawmed.vercel.app',
  ],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ============================================
// MONGODB CONNECTION (native driver, no Mongoose)
// ============================================
//
// IMPORTANT: Better Auth writes its own `user` documents into this same
// database/collection. We deliberately do NOT define a schema for `user`
// here — we read/write it exactly as Better Auth created it, so there is
// no casting mismatch between Better Auth's writes and this API's reads.

let client: MongoClient;
let db: Db;

let Users: Collection<any>;
let Pets: Collection<any>;
let Appointments: Collection<any>;
let Services: Collection<any>;
let Prescriptions: Collection<any>;
let Payments: Collection<any>;
let MedicalRecords: Collection<any>;

const connectDB = async () => {
  try {
    client = new MongoClient(process.env.MONGODB_URI || 'mongodb://localhost:27017/pawmed');
    await client.connect();
    db = client.db('pawmed');

    Users = db.collection('user'); // matches Better Auth's collection name exactly
    Pets = db.collection('pets');
    Appointments = db.collection('appointments');
    Services = db.collection('services');
    Prescriptions = db.collection('prescriptions');
    Payments = db.collection('payments');
    MedicalRecords = db.collection('medicalrecords');

    console.log('✅ MongoDB Connected to pawmed database (native driver)');
  } catch (error: any) {
    console.error('❌ MongoDB Error:', error.message);
    // Locally we want a hard crash so the problem is obvious immediately.
    // On Vercel we do NOT want to kill the whole process — throw instead
    // so the caller (ensureDbConnected below) can turn it into a clean
    // 500 response for just that one request, and the next invocation
    // gets to try connecting again.
    if (!process.env.VERCEL) {
      process.exit(1);
    }
    throw error;
  }
};

// ============================================
// SERVERLESS-SAFE DB CONNECTION
// ============================================
//
// On Vercel, this module is imported once per cold start and then reused
// across warm invocations of the same function instance — but Vercel
// NEVER calls app.listen(). We connect lazily on first use and cache the
// in-flight/completed connection promise so every request after the
// first one on a warm instance is instant.

let dbConnectionPromise: Promise<void> | null = null;

const ensureDbConnected = (): Promise<void> => {
  if (!dbConnectionPromise) {
    dbConnectionPromise = connectDB().catch((err) => {
      // Reset so the NEXT request gets to retry the connection instead
      // of being permanently stuck on one failed attempt.
      dbConnectionPromise = null;
      throw err;
    });
  }
  return dbConnectionPromise;
};

// Runs before every route. Cheap no-op once warm; on a cold start it
// awaits the real connection before letting any route touch a collection.
app.use(async (_req: Request, res: Response, next: NextFunction) => {
  try {
    await ensureDbConnected();
    next();
  } catch (err: any) {
    res.status(503).json({
      success: false,
      message: 'Database connection failed — check MONGODB_URI is set correctly in your deployment environment variables.'
    });
  }
});

// ============================================
// TYPES (documentation only — not enforced at runtime)
// ============================================

interface IUser extends MongoDoc {
  _id: any; // Better Auth controls this — could be string or ObjectId depending on its config
  name?: string;
  email: string;
  role: 'admin' | 'veterinarian' | 'client';
  phone?: string;
  address?: string;
  profileImage?: string;
  specialization?: string[];
  licenseNumber?: string;
  experience?: number;
  isActive?: boolean;
  emailVerified?: boolean;
}

// ============================================
// HELPERS
// ============================================

// Users may have either a string or ObjectId _id depending on Better Auth's
// configuration, so every place we need to reference "this user" we keep
// the original _id value as-is (no forced ObjectId casting) and compare
// with String(...) for safety.
const idsMatch = (a: any, b: any) => String(a) === String(b);

// Safely turn a route param into an ObjectId; returns null if invalid
// instead of throwing, so routes can return a clean 400/404.
const toObjectId = (id: unknown): ObjectId | null => {
  try {
    return new ObjectId(String(id));
  } catch {
    return null;
  }
};

// Shared $lookup + $unwind stage for joining a "user-like" reference field
// (client, veterinarian, owner, prescribedBy, etc.) stored as whatever type
// Better Auth uses for _id, projecting only safe public fields.
function lookupUser(localField: string, as: string, preserveNull = true) {
  return [
    {
      $lookup: {
        from: 'user',
        localField,
        foreignField: '_id',
        as,
      },
    },
    {
      $unwind: {
        path: `$${as}`,
        preserveNullAndEmptyArrays: preserveNull,
      },
    },
    {
      $addFields: {
        [as]: {
          _id: `$${as}._id`,
          name: `$${as}.name`,
          email: `$${as}.email`,
          phone: `$${as}.phone`,
          address: `$${as}.address`,
          specialization: `$${as}.specialization`,
        },
      },
    },
  ];
}

function lookupPet(localField: string, as: string, preserveNull = true) {
  return [
    {
      $lookup: {
        from: 'pets',
        localField,
        foreignField: '_id',
        as,
      },
    },
    {
      $unwind: {
        path: `$${as}`,
        preserveNullAndEmptyArrays: preserveNull,
      },
    },
  ];
}

// ============================================
// AUTH MIDDLEWARE (session-based via Next.js proxy, no shared secret)
// ============================================
//
// The Next.js server owns the Better Auth session/cookie and has already
// verified the caller's identity before it ever reaches Express. The
// Next.js proxy route sends one header on every request to Express:
//
//   x-user-email : the email of the already-authenticated user
//
// Express looks the user up by email and attaches it to req.user.
//
// TRUST BOUNDARY: there is no shared secret anymore, so Express must NOT
// be reachable directly from the public internet or from anything other
// than the Next.js server — otherwise anyone could spoof x-user-email.
// Keep Express on a private network / localhost-only in production.

interface AuthRequest extends Request {
  user?: IUser;
}

const auth = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const userEmail = req.header('x-user-email');

    if (!userEmail) {
      res.status(401).json({ message: 'Missing user identity' });
      return;
    }

    const user = await Users.findOne({ email: userEmail.toLowerCase() }) as IUser | null;

    if (!user) {
      res.status(401).json({ message: 'User not found' });
      return;
    }

    if (user.isActive === false) {
      res.status(401).json({ message: 'User account is deactivated' });
      return;
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Authentication failed' });
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
// ROOT ROUTE
// ============================================

app.get('/', (_req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: '🏥 Welcome to PawMed Veterinary Clinic API',
    docs: {
      health: '/api/health',
      me: '/api/auth/me (requires x-user-email, via the Next.js proxy)',
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

app.get('/api/auth/me', auth, async (req: AuthRequest, res: Response) => {
  try {
    return res.status(200).json({
      success: true,
      data: { user: req.user }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.put('/api/auth/profile', auth, async (req: AuthRequest, res: Response) => {
  try {
    const { name, phone, address, profileImage } = req.body;
    const userId = req.user?._id;

    const result = await Users.findOneAndUpdate(
      { _id: userId },
      { $set: { name, phone, address, profileImage } },
      { returnDocument: 'after' }
    );

    if (!result) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: { user: result }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

// ============================================
// PET ROUTES
// ============================================

app.post('/api/pets', auth, async (req: AuthRequest, res: Response) => {
  try {
    const petData = {
      ...req.body,
      owner: req.user?._id,
      medicalHistory: req.body.medicalHistory ?? [],
      allergies: req.body.allergies ?? [],
      chronicConditions: req.body.chronicConditions ?? [],
      currentMedications: req.body.currentMedications ?? [],
      vaccinationHistory: req.body.vaccinationHistory ?? [],
      isActive: true,
      profileImage: req.body.profileImage || 'https://ui-avatars.com/api/?background=random&name=Pet',
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await Pets.insertOne(petData);
    const pet = await Pets.findOne({ _id: result.insertedId });

    return res.status(201).json({
      success: true,
      message: 'Pet created successfully',
      data: { pet }
    });
  } catch (error: any) {
    console.error('Pet Creation Error:', error);
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/pets', auth, async (req: AuthRequest, res: Response) => {
  try {
    const { search = '', species } = req.query;
    const match: Filter<any> = {};

    if (req.user?.role === 'client') {
      match.owner = req.user._id;
    }

    if (search) {
      match.$or = [
        { name: { $regex: search, $options: 'i' } },
        { species: { $regex: search, $options: 'i' } },
        { breed: { $regex: search, $options: 'i' } }
      ];
    }

    if (species) match.species = species;

    const pets = await Pets.aggregate([
      { $match: match },
      ...lookupUser('owner', 'owner'),
      { $sort: { createdAt: -1 } },
    ]).toArray();

    return res.status(200).json({ success: true, data: { pets } });
  } catch (error: any) {
    console.error('Get Pets Error:', error);
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/pets/:id', auth, async (req: Request, res: Response) => {
  try {
    const petId = toObjectId(req.params.id);
    if (!petId) return res.status(400).json({ message: 'Invalid pet id' });

    const results = await Pets.aggregate([
      { $match: { _id: petId } },
      ...lookupUser('owner', 'owner'),
    ]).toArray();

    const pet = results[0];
    if (!pet) return res.status(404).json({ message: 'Pet not found' });

    return res.status(200).json({ success: true, data: { pet } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.put('/api/pets/:id', auth, async (req: Request, res: Response) => {
  try {
    const petId = toObjectId(req.params.id);
    if (!petId) return res.status(400).json({ message: 'Invalid pet id' });

    const result = await Pets.findOneAndUpdate(
      { _id: petId },
      { $set: { ...req.body, updatedAt: new Date() } },
      { returnDocument: 'after' }
    );

    if (!result) return res.status(404).json({ message: 'Pet not found' });

    return res.status(200).json({
      success: true,
      message: 'Pet updated successfully',
      data: { pet: result }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.delete('/api/pets/:id', auth, async (req: Request, res: Response) => {
  try {
    const petId = toObjectId(req.params.id);
    if (!petId) return res.status(400).json({ message: 'Invalid pet id' });

    const result = await Pets.findOneAndDelete({ _id: petId });
    if (!result) return res.status(404).json({ message: 'Pet not found' });

    return res.status(200).json({ success: true, message: 'Pet deleted successfully' });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

// ============================================
// APPOINTMENT ROUTES
// ============================================

app.post('/api/appointments', auth, async (req: AuthRequest, res: Response) => {
  try {
    const { petId, veterinarianId, appointmentType, date, time, symptoms, notes, priority, amount } = req.body;

    const petObjectId = toObjectId(petId);
    if (!petObjectId) return res.status(400).json({ message: 'Invalid pet id' });

    const pet = await Pets.findOne({ _id: petObjectId, owner: req.user?._id });
    if (!pet) {
      return res.status(404).json({ message: 'Pet not found or not owned by user' });
    }

    const veterinarian = await Users.findOne({ _id: veterinarianId, role: 'veterinarian' });
    if (!veterinarian) {
      return res.status(404).json({ message: 'Veterinarian not found' });
    }

    const conflictingAppointment = await Appointments.findOne({
      veterinarian: veterinarianId,
      date: new Date(date),
      time,
      status: { $in: ['scheduled', 'confirmed'] }
    });

    if (conflictingAppointment) {
      return res.status(400).json({ message: 'Veterinarian is not available at this time' });
    }

    const appointmentDoc = {
      client: req.user?._id,
      pet: petObjectId,
      veterinarian: veterinarianId,
      appointmentType,
      date: new Date(date),
      time,
      duration: 30,
      status: 'scheduled',
      symptoms: symptoms ?? [],
      priority: priority || 'normal',
      notes,
      paymentStatus: 'pending',
      amount: amount || 0,
      reminderSent: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await Appointments.insertOne(appointmentDoc);

    const populated = await Appointments.aggregate([
      { $match: { _id: result.insertedId } },
      ...lookupUser('client', 'client'),
      ...lookupUser('veterinarian', 'veterinarian'),
      ...lookupPet('pet', 'pet'),
    ]).toArray();

    return res.status(201).json({
      success: true,
      message: 'Appointment created successfully',
      data: { appointment: populated[0] }
    });
  } catch (error: any) {
    console.error('Appointment Creation Error:', error);
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/appointments', auth, async (req: AuthRequest, res: Response) => {
  try {
    const { status, dateFrom, dateTo } = req.query;
    const match: Filter<any> = {};

    if (req.user?.role === 'client') {
      match.client = req.user._id;
    } else if (req.user?.role === 'veterinarian') {
      match.veterinarian = req.user._id;
    }

    if (status) match.status = status;
    if (dateFrom || dateTo) {
      match.date = {};
      if (dateFrom) match.date.$gte = new Date(dateFrom as string);
      if (dateTo) match.date.$lte = new Date(dateTo as string);
    }

    const appointments = await Appointments.aggregate([
      { $match: match },
      ...lookupUser('client', 'client'),
      ...lookupUser('veterinarian', 'veterinarian'),
      ...lookupPet('pet', 'pet'),
      { $sort: { date: 1, time: 1 } },
    ]).toArray();

    return res.status(200).json({ success: true, data: { appointments } });
  } catch (error: any) {
    console.error('Get Appointments Error:', error);
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/appointments/:id', auth, async (req: Request, res: Response) => {
  try {
    const apptId = toObjectId(req.params.id);
    if (!apptId) return res.status(400).json({ message: 'Invalid appointment id' });

    const results = await Appointments.aggregate([
      { $match: { _id: apptId } },
      ...lookupUser('client', 'client'),
      ...lookupUser('veterinarian', 'veterinarian'),
      ...lookupPet('pet', 'pet'),
    ]).toArray();

    const appointment = results[0];
    if (!appointment) return res.status(404).json({ message: 'Appointment not found' });

    return res.status(200).json({ success: true, data: { appointment } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.put('/api/appointments/:id/status', auth, roleCheck('veterinarian', 'admin'), async (req: Request, res: Response) => {
  try {
    const apptId = toObjectId(req.params.id);
    if (!apptId) return res.status(400).json({ message: 'Invalid appointment id' });

    const { status, notes } = req.body;

    const result = await Appointments.findOneAndUpdate(
      { _id: apptId },
      { $set: { status, notes, updatedAt: new Date() } },
      { returnDocument: 'after' }
    );

    if (!result) return res.status(404).json({ message: 'Appointment not found' });

    const populated = await Appointments.aggregate([
      { $match: { _id: apptId } },
      ...lookupUser('client', 'client'),
      ...lookupUser('veterinarian', 'veterinarian'),
      ...lookupPet('pet', 'pet'),
    ]).toArray();

    return res.status(200).json({
      success: true,
      message: 'Appointment status updated successfully',
      data: { appointment: populated[0] }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.put('/api/appointments/:id/cancel', auth, async (req: Request, res: Response) => {
  try {
    const apptId = toObjectId(req.params.id);
    if (!apptId) return res.status(400).json({ message: 'Invalid appointment id' });

    const result = await Appointments.findOneAndUpdate(
      { _id: apptId },
      { $set: { status: 'cancelled', updatedAt: new Date() } },
      { returnDocument: 'after' }
    );

    if (!result) return res.status(404).json({ message: 'Appointment not found' });

    return res.status(200).json({
      success: true,
      message: 'Appointment cancelled successfully',
      data: { appointment: result }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

// ============================================
// SERVICE ROUTES
// ============================================

app.get('/api/services', async (req: Request, res: Response) => {
  try {
    const { category, search, minPrice, maxPrice } = req.query;
    const match: Filter<any> = { isAvailable: true };

    if (category) match.category = category;
    if (search) {
      match.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    if (minPrice || maxPrice) {
      match.price = {};
      if (minPrice) match.price.$gte = Number(minPrice);
      if (maxPrice) match.price.$lte = Number(maxPrice);
    }

    const services = await Services.find(match).sort({ price: 1 }).toArray();

    return res.status(200).json({ success: true, data: { services } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/services/:id', async (req: Request, res: Response) => {
  try {
    const serviceId = toObjectId(req.params.id);
    if (!serviceId) return res.status(400).json({ message: 'Invalid service id' });

    const service = await Services.findOne({ _id: serviceId });
    if (!service) return res.status(404).json({ message: 'Service not found' });

    return res.status(200).json({ success: true, data: { service } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.post('/api/services', auth, roleCheck('admin'), async (req: Request, res: Response) => {
  try {
    const doc = {
      ...req.body,
      isAvailable: req.body.isAvailable ?? true,
      requiresSpecialist: req.body.requiresSpecialist ?? false,
      image: req.body.image || 'https://via.placeholder.com/300x200?text=Service',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const result = await Services.insertOne(doc);
    const service = await Services.findOne({ _id: result.insertedId });

    return res.status(201).json({
      success: true,
      message: 'Service created successfully',
      data: { service }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.put('/api/services/:id', auth, roleCheck('admin'), async (req: Request, res: Response) => {
  try {
    const serviceId = toObjectId(req.params.id);
    if (!serviceId) return res.status(400).json({ message: 'Invalid service id' });

    const result = await Services.findOneAndUpdate(
      { _id: serviceId },
      { $set: { ...req.body, updatedAt: new Date() } },
      { returnDocument: 'after' }
    );

    if (!result) return res.status(404).json({ message: 'Service not found' });

    return res.status(200).json({
      success: true,
      message: 'Service updated successfully',
      data: { service: result }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.delete('/api/services/:id', auth, roleCheck('admin'), async (req: Request, res: Response) => {
  try {
    const serviceId = toObjectId(req.params.id);
    if (!serviceId) return res.status(400).json({ message: 'Invalid service id' });

    const result = await Services.findOneAndDelete({ _id: serviceId });
    if (!result) return res.status(404).json({ message: 'Service not found' });

    return res.status(200).json({ success: true, message: 'Service deleted successfully' });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

// ============================================
// PRESCRIPTION ROUTES
// ============================================

app.post('/api/prescriptions', auth, roleCheck('veterinarian', 'admin'), async (req: AuthRequest, res: Response) => {
  try {
    const { petId, medications, diagnosis, notes, validUntil, isRefillable, refillsRemaining } = req.body;

    const petObjectId = toObjectId(petId);
    if (!petObjectId) return res.status(400).json({ message: 'Invalid pet id' });

    const pet = await Pets.findOne({ _id: petObjectId });
    if (!pet) return res.status(404).json({ message: 'Pet not found' });

    const doc = {
      pet: petObjectId,
      veterinarian: req.user?._id,
      client: pet.owner,
      medications,
      diagnosis,
      notes,
      issuedDate: new Date(),
      validUntil: new Date(validUntil),
      isActive: true,
      isRefillable: isRefillable || false,
      refillsRemaining: refillsRemaining || 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await Prescriptions.insertOne(doc);

    const populated = await Prescriptions.aggregate([
      { $match: { _id: result.insertedId } },
      ...lookupPet('pet', 'pet'),
      ...lookupUser('veterinarian', 'veterinarian'),
      ...lookupUser('client', 'client'),
    ]).toArray();

    return res.status(201).json({
      success: true,
      message: 'Prescription created successfully',
      data: { prescription: populated[0] }
    });
  } catch (error: any) {
    console.error('Prescription Creation Error:', error);
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/prescriptions', auth, async (req: AuthRequest, res: Response) => {
  try {
    const match: Filter<any> = {};

    if (req.user?.role === 'client') {
      match.client = req.user._id;
    } else if (req.user?.role === 'veterinarian') {
      match.veterinarian = req.user._id;
    }

    const prescriptions = await Prescriptions.aggregate([
      { $match: match },
      ...lookupPet('pet', 'pet'),
      ...lookupUser('veterinarian', 'veterinarian'),
      ...lookupUser('client', 'client'),
      { $sort: { createdAt: -1 } },
    ]).toArray();

    return res.status(200).json({ success: true, data: { prescriptions } });
  } catch (error: any) {
    console.error('Get Prescriptions Error:', error);
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/prescriptions/:id', auth, async (req: Request, res: Response) => {
  try {
    const presId = toObjectId(req.params.id);
    if (!presId) return res.status(400).json({ message: 'Invalid prescription id' });

    const results = await Prescriptions.aggregate([
      { $match: { _id: presId } },
      ...lookupPet('pet', 'pet'),
      ...lookupUser('veterinarian', 'veterinarian'),
      ...lookupUser('client', 'client'),
    ]).toArray();

    const prescription = results[0];
    if (!prescription) return res.status(404).json({ message: 'Prescription not found' });

    return res.status(200).json({ success: true, data: { prescription } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.put('/api/prescriptions/:id', auth, roleCheck('veterinarian', 'admin'), async (req: Request, res: Response) => {
  try {
    const presId = toObjectId(req.params.id);
    if (!presId) return res.status(400).json({ message: 'Invalid prescription id' });

    const result = await Prescriptions.findOneAndUpdate(
      { _id: presId },
      { $set: { ...req.body, updatedAt: new Date() } },
      { returnDocument: 'after' }
    );

    if (!result) return res.status(404).json({ message: 'Prescription not found' });

    return res.status(200).json({
      success: true,
      message: 'Prescription updated successfully',
      data: { prescription: result }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.delete('/api/prescriptions/:id', auth, roleCheck('veterinarian', 'admin'), async (req: Request, res: Response) => {
  try {
    const presId = toObjectId(req.params.id);
    if (!presId) return res.status(400).json({ message: 'Invalid prescription id' });

    const result = await Prescriptions.findOneAndDelete({ _id: presId });
    if (!result) return res.status(404).json({ message: 'Prescription not found' });

    return res.status(200).json({ success: true, message: 'Prescription deleted successfully' });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

// ============================================
// PAYMENT ROUTES
// ============================================

app.post('/api/payments', auth, async (req: AuthRequest, res: Response) => {
  try {
    const { appointmentId, amount, paymentMethod, stripePaymentId } = req.body;

    const apptObjectId = toObjectId(appointmentId);
    if (!apptObjectId) return res.status(400).json({ success: false, message: 'Invalid appointment id' });

    const appointment = await Appointments.findOne({ _id: apptObjectId });
    if (!appointment) {
      return res.status(404).json({ success: false, message: 'Appointment not found' });
    }

    if (!idsMatch(appointment.client, req.user?._id)) {
      return res.status(403).json({ success: false, message: 'Not authorized to pay for this appointment' });
    }

    if (appointment.paymentStatus === 'paid') {
      return res.status(400).json({ success: false, message: 'Appointment already paid' });
    }

    const generatedStripeId = stripePaymentId || `pi_${Date.now()}`;

    const doc = {
      appointment: apptObjectId,
      user: req.user?._id,
      amount: amount || appointment.amount || 0,
      currency: 'usd',
      stripePaymentId: generatedStripeId,
      status: 'succeeded',
      paymentMethod: paymentMethod || 'card',
      receiptUrl: `https://receipt.stripe.com/${generatedStripeId}`,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await Payments.insertOne(doc);

    await Appointments.updateOne(
      { _id: apptObjectId },
      { $set: { paymentStatus: 'paid', paymentId: generatedStripeId, amount: doc.amount, updatedAt: new Date() } }
    );

    const populated = await Payments.aggregate([
      { $match: { _id: result.insertedId } },
      {
        $lookup: {
          from: 'appointments',
          localField: 'appointment',
          foreignField: '_id',
          as: 'appointment',
        },
      },
      { $unwind: { path: '$appointment', preserveNullAndEmptyArrays: true } },
      ...lookupUser('user', 'user'),
    ]).toArray();

    return res.status(201).json({
      success: true,
      message: 'Payment created successfully',
      data: { payment: populated[0] }
    });
  } catch (error: any) {
    console.error('Payment Creation Error:', error);
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/payments', auth, async (req: AuthRequest, res: Response) => {
  try {
    const match: Filter<any> = {};

    if (req.user?.role === 'client') {
      match.user = req.user._id;
    }

    const payments = await Payments.aggregate([
      { $match: match },
      {
        $lookup: {
          from: 'appointments',
          localField: 'appointment',
          foreignField: '_id',
          as: 'appointment',
        },
      },
      { $unwind: { path: '$appointment', preserveNullAndEmptyArrays: true } },
      ...lookupUser('user', 'user'),
      { $sort: { createdAt: -1 } },
    ]).toArray();

    return res.status(200).json({ success: true, data: { payments } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/payments/:id', auth, async (req: Request, res: Response) => {
  try {
    const paymentId = toObjectId(req.params.id);
    if (!paymentId) return res.status(400).json({ success: false, message: 'Invalid payment id' });

    const results = await Payments.aggregate([
      { $match: { _id: paymentId } },
      {
        $lookup: {
          from: 'appointments',
          localField: 'appointment',
          foreignField: '_id',
          as: 'appointment',
        },
      },
      { $unwind: { path: '$appointment', preserveNullAndEmptyArrays: true } },
      ...lookupUser('user', 'user'),
    ]).toArray();

    const payment = results[0];
    if (!payment) return res.status(404).json({ success: false, message: 'Payment not found' });

    return res.status(200).json({ success: true, data: { payment } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/payments/appointment/:appointmentId', auth, async (req: Request, res: Response) => {
  try {
    const apptId = toObjectId(req.params.appointmentId);
    if (!apptId) return res.status(400).json({ success: false, message: 'Invalid appointment id' });

    const results = await Payments.aggregate([
      { $match: { appointment: apptId } },
      {
        $lookup: {
          from: 'appointments',
          localField: 'appointment',
          foreignField: '_id',
          as: 'appointment',
        },
      },
      { $unwind: { path: '$appointment', preserveNullAndEmptyArrays: true } },
      ...lookupUser('user', 'user'),
    ]).toArray();

    const payment = results[0];
    if (!payment) {
      return res.status(404).json({ success: false, message: 'Payment not found for this appointment' });
    }

    return res.status(200).json({ success: true, data: { payment } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

// ============================================
// MEDICAL RECORD ROUTES
// ============================================

app.post('/api/medicalrecords', auth, roleCheck('veterinarian', 'admin'), async (req: AuthRequest, res: Response) => {
  try {
    const petObjectId = toObjectId(req.body.pet);
    const apptObjectId = toObjectId(req.body.appointment);
    if (!petObjectId) return res.status(400).json({ message: 'Invalid pet id' });
    if (!apptObjectId) return res.status(400).json({ message: 'Invalid appointment id' });

    const pet = await Pets.findOne({ _id: petObjectId });
    if (!pet) return res.status(404).json({ message: 'Pet not found' });

    const doc = {
      ...req.body,
      pet: petObjectId,
      appointment: apptObjectId,
      veterinarian: req.user?._id,
      visitDate: req.body.visitDate ? new Date(req.body.visitDate) : new Date(),
      medications: req.body.medications ?? [],
      isEmergency: req.body.isEmergency ?? false,
      status: req.body.status || 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await MedicalRecords.insertOne(doc);

    await Pets.updateOne({ _id: petObjectId }, { $set: { lastVisit: new Date() } });

    const populated = await MedicalRecords.aggregate([
      { $match: { _id: result.insertedId } },
      ...lookupPet('pet', 'pet'),
      ...lookupUser('veterinarian', 'veterinarian'),
      {
        $lookup: {
          from: 'appointments',
          localField: 'appointment',
          foreignField: '_id',
          as: 'appointment',
        },
      },
      { $unwind: { path: '$appointment', preserveNullAndEmptyArrays: true } },
    ]).toArray();

    return res.status(201).json({
      success: true,
      message: 'Medical record created successfully',
      data: { medicalRecord: populated[0] }
    });
  } catch (error: any) {
    console.error('Medical Record Creation Error:', error);
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/medicalrecords', auth, async (req: AuthRequest, res: Response) => {
  try {
    const { petId, status } = req.query;
    const match: Filter<any> = {};

    if (petId) {
      const petObjectId = toObjectId(petId as string);
      if (petObjectId) match.pet = petObjectId;
    }
    if (status) match.status = status;

    if (req.user?.role === 'client') {
      const pets = await Pets.find({ owner: req.user._id }).project({ _id: 1 }).toArray();
      match.pet = { $in: pets.map((p) => p._id) };
    } else if (req.user?.role === 'veterinarian') {
      match.veterinarian = req.user._id;
    }

    const medicalRecords = await MedicalRecords.aggregate([
      { $match: match },
      ...lookupPet('pet', 'pet'),
      ...lookupUser('veterinarian', 'veterinarian'),
      {
        $lookup: {
          from: 'appointments',
          localField: 'appointment',
          foreignField: '_id',
          as: 'appointment',
        },
      },
      { $unwind: { path: '$appointment', preserveNullAndEmptyArrays: true } },
      { $sort: { visitDate: -1 } },
    ]).toArray();

    return res.status(200).json({ success: true, data: { medicalRecords } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/medicalrecords/:id', auth, async (req: Request, res: Response) => {
  try {
    const recordId = toObjectId(req.params.id);
    if (!recordId) return res.status(400).json({ message: 'Invalid medical record id' });

    const results = await MedicalRecords.aggregate([
      { $match: { _id: recordId } },
      ...lookupPet('pet', 'pet'),
      ...lookupUser('veterinarian', 'veterinarian'),
      {
        $lookup: {
          from: 'appointments',
          localField: 'appointment',
          foreignField: '_id',
          as: 'appointment',
        },
      },
      { $unwind: { path: '$appointment', preserveNullAndEmptyArrays: true } },
    ]).toArray();

    const medicalRecord = results[0];
    if (!medicalRecord) return res.status(404).json({ message: 'Medical record not found' });

    return res.status(200).json({ success: true, data: { medicalRecord } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.put('/api/medicalrecords/:id', auth, roleCheck('veterinarian', 'admin'), async (req: Request, res: Response) => {
  try {
    const recordId = toObjectId(req.params.id);
    if (!recordId) return res.status(400).json({ message: 'Invalid medical record id' });

    const result = await MedicalRecords.findOneAndUpdate(
      { _id: recordId },
      { $set: { ...req.body, updatedAt: new Date() } },
      { returnDocument: 'after' }
    );

    if (!result) return res.status(404).json({ message: 'Medical record not found' });

    return res.status(200).json({
      success: true,
      message: 'Medical record updated successfully',
      data: { medicalRecord: result }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.delete('/api/medicalrecords/:id', auth, roleCheck('veterinarian', 'admin'), async (req: Request, res: Response) => {
  try {
    const recordId = toObjectId(req.params.id);
    if (!recordId) return res.status(400).json({ message: 'Invalid medical record id' });

    const result = await MedicalRecords.findOneAndDelete({ _id: recordId });
    if (!result) return res.status(404).json({ message: 'Medical record not found' });

    return res.status(200).json({ success: true, message: 'Medical record deleted successfully' });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

// ============================================
// ADMIN ROUTES
// ============================================

app.get('/api/admin/dashboard', auth, roleCheck('admin'), async (_req: Request, res: Response) => {
  try {
    const [
      totalUsers,
      totalPets,
      totalAppointments,
      totalServices,
      totalPrescriptions,
      totalPayments,
      pendingAppointments
    ] = await Promise.all([
      Users.countDocuments(),
      Pets.countDocuments(),
      Appointments.countDocuments(),
      Services.countDocuments(),
      Prescriptions.countDocuments(),
      Payments.countDocuments(),
      Appointments.countDocuments({ status: 'scheduled' })
    ]);

    const stats = {
      totalUsers,
      totalPets,
      totalAppointments,
      totalServices,
      totalPrescriptions,
      totalPayments,
      pendingAppointments
    };

    return res.status(200).json({ success: true, data: stats });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/admin/users', auth, roleCheck('admin'), async (_req: Request, res: Response) => {
  try {
    const users = await Users.find().sort({ createdAt: -1 }).toArray();
    return res.status(200).json({
      success: true,
      message: 'Users fetched successfully',
      data: { users }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.put('/api/admin/users/:id/role', auth, roleCheck('admin'), async (req: Request, res: Response) => {
  try {
    const { role } = req.body;

    if (!['admin', 'veterinarian', 'client'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    // User _id type is whatever Better Auth uses (often a string) — do NOT
    // force ObjectId conversion here, match on the raw param instead. Try
    // both string and ObjectId forms to be safe.
    const idParam = req.params.id;
    const objId = toObjectId(idParam);
    const filter: Filter<any> = objId ? { $or: [{ _id: idParam }, { _id: objId }] } : { _id: idParam };

    const result = await Users.findOneAndUpdate(
      filter,
      { $set: { role } },
      { returnDocument: 'after' }
    );

    if (!result) return res.status(404).json({ message: 'User not found' });

    return res.status(200).json({
      success: true,
      message: 'User role updated successfully',
      data: { user: result }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.put('/api/admin/users/:id/toggle', auth, roleCheck('admin'), async (req: Request, res: Response) => {
  try {
    const idParam = req.params.id;
    const objId = toObjectId(idParam);
    const filter: Filter<any> = objId ? { $or: [{ _id: idParam }, { _id: objId }] } : { _id: idParam };

    const user = await Users.findOne(filter);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const newActive = !(user.isActive ?? true);

    const result = await Users.findOneAndUpdate(
      filter,
      { $set: { isActive: newActive } },
      { returnDocument: 'after' }
    );

    return res.status(200).json({
      success: true,
      message: `User ${newActive ? 'activated' : 'deactivated'} successfully`,
      data: { user: result }
    });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

// ============================================
// VETERINARIAN ROUTES
// ============================================

app.get('/api/veterinarian/appointments', auth, roleCheck('veterinarian'), async (req: AuthRequest, res: Response) => {
  try {
    const { status, date } = req.query;
    const match: Filter<any> = { veterinarian: req.user?._id };

    if (status) match.status = status;
    if (date) match.date = new Date(date as string);

    const appointments = await Appointments.aggregate([
      { $match: match },
      ...lookupUser('client', 'client'),
      ...lookupPet('pet', 'pet'),
      { $sort: { date: 1, time: 1 } },
    ]).toArray();

    return res.status(200).json({ success: true, data: { appointments } });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

app.get('/api/veterinarian/stats', auth, roleCheck('veterinarian'), async (req: AuthRequest, res: Response) => {
  try {
    const vetId = req.user?._id;
    const todayStart = new Date(new Date().setHours(0, 0, 0, 0));
    const todayEnd = new Date(new Date().setHours(23, 59, 59, 999));

    const [
      totalAppointments,
      completedAppointments,
      pendingAppointments,
      todayAppointments,
      totalPrescriptions
    ] = await Promise.all([
      Appointments.countDocuments({ veterinarian: vetId }),
      Appointments.countDocuments({ veterinarian: vetId, status: 'completed' }),
      Appointments.countDocuments({ veterinarian: vetId, status: 'scheduled' }),
      Appointments.countDocuments({ veterinarian: vetId, date: { $gte: todayStart, $lt: todayEnd } }),
      Prescriptions.countDocuments({ veterinarian: vetId })
    ]);

    const stats = {
      totalAppointments,
      completedAppointments,
      pendingAppointments,
      todayAppointments,
      totalPrescriptions,
      completionRate: totalAppointments > 0
        ? Math.round((completedAppointments / totalAppointments) * 100)
        : 0
    };

    return res.status(200).json({ success: true, data: stats });
  } catch (error: any) {
    return res.status(500).json({ success: false, message: error.message || 'Server Error' });
  }
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'success',
    message: '🏥 PawMed Veterinary Clinic API is running',
    timestamp: new Date().toISOString()
  });
});

// ============================================
// 404 HANDLER
// ============================================

app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`
  });
});

// ============================================
// ERROR HANDLER
// ============================================

app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Error:', err);

  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0];

    return res.status(400).json({
      success: false,
      message: `Duplicate value entered for ${field} field`
    });
  }

  return res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ============================================
// SEED DATABASE
// ============================================

const seedDatabase = async () => {
  try {
    const services = [
      {
        name: 'General Health Checkup',
        description: 'Comprehensive physical examination including vital signs, weight check, and overall health assessment',
        category: 'consultation',
        price: 60,
        duration: 30,
        isAvailable: true,
        requiresSpecialist: false
      },
      {
        name: 'Vaccination Package',
        description: 'Complete vaccination including rabies, distemper, and parvovirus vaccines',
        category: 'vaccination',
        price: 85,
        duration: 20,
        isAvailable: true,
        requiresSpecialist: false
      },
      {
        name: 'Spay/Neuter Surgery',
        description: 'Surgical sterilization procedure with pre-surgical blood work and post-operative care',
        category: 'surgery',
        price: 350,
        duration: 90,
        isAvailable: true,
        requiresSpecialist: true
      },
      {
        name: 'Dental Cleaning',
        description: 'Professional teeth cleaning, scaling, and polishing under anesthesia',
        category: 'dental',
        price: 250,
        duration: 60,
        isAvailable: true,
        requiresSpecialist: false
      },
      {
        name: 'Emergency Care',
        description: '24/7 emergency medical care for critical conditions',
        category: 'emergency',
        price: 200,
        duration: 60,
        isAvailable: true,
        requiresSpecialist: true
      }
    ];

    for (const serviceData of services) {
      const exists = await Services.findOne({ name: serviceData.name });
      if (!exists) {
        await Services.insertOne({
          ...serviceData,
          image: 'https://via.placeholder.com/300x200?text=Service',
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        console.log(`✅ Service created: ${serviceData.name}`);
      }
    }

    console.log('✅ Services seeded successfully');
    console.log('\n📋 To create your first admin/vet account:');
    console.log("  1. Register at your app's sign-up page (creates a client)");
    console.log('  2. Promote the role in MongoDB, e.g.:');
    console.log('     db.user.updateOne({ email: "you@example.com" }, { $set: { role: "admin" } })');
  } catch (error: any) {
    console.error('❌ Error seeding database:', error.message);
  }
};

// ============================================
// START SERVER
// ============================================
//
// Locally (run via `node`/`ts-node`, no VERCEL env var present), this
// boots a normal long-running server on PORT and seeds Services.
//
// On Vercel, the platform imports this module once per cold start and
// then calls the exported `app` directly per request — it never calls
// app.listen(). The DB connection is instead established lazily by the
// `ensureDbConnected` middleware registered near the top of this file,
// so we skip listen()/seeding entirely when process.env.VERCEL is set.

if (!process.env.VERCEL) {
  const startServer = async () => {
    await connectDB();

    if (process.env.NODE_ENV === 'development') {
      await seedDatabase();
    }

    app.listen(PORT, () => {
      console.log(`\n🏥 PawMed Veterinary Clinic API running on port ${PORT}`);
      console.log(`📚 Health Check: http://localhost:${PORT}/api/health`);
      console.log(`🐾 Pets: http://localhost:${PORT}/api/pets`);
      console.log(`📋 Services: http://localhost:${PORT}/api/services`);
      console.log(`💊 Prescriptions: http://localhost:${PORT}/api/prescriptions`);
      console.log(`💰 Payments: http://localhost:${PORT}/api/payments`);
      console.log(`📋 Medical Records: http://localhost:${PORT}/api/medicalrecords`);
      console.log(`📊 Admin Dashboard: http://localhost:${PORT}/api/admin/dashboard`);
      console.log('\n⚠️  Auth is cookie/session based via the Next.js proxy — no shared secret.');
    });
  };

  startServer();
}

export default app;