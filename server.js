const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);

// Set up security headers with helmet
app.use(helmet({
  contentSecurityPolicy: false // Allow inline scripts and bootstrap/font CDNs for simple rendering
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Set up EJS view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session Security Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'paint-shop-saas-production-security-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8 // 8 hours
  }
}));

// Rate Limiters
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts. Please try again later.'
});

const forgotLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many password reset requests. Please try again later.'
});

const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many password reset attempts. Please try again later.'
});

// Middleware for CSRF Token generation and verification
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  }

  // Exempt GET, HEAD, OPTIONS from CSRF verification
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const clientToken = req.body._csrf || req.headers['x-csrf-token'];
  if (!clientToken || clientToken !== req.session.csrfToken) {
    return res.status(403).send('CSRF Token Mismatch / Forbidden.');
  }
  next();
});

// MONGOOSE SCHEMAS AND MODELS
const ShopSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  owner_name: { type: String, required: true, trim: true },
  email: { type: String, required: true, lowercase: true, trim: true },
  phone: { type: String, trim: true, default: '' },
  address: { type: String, trim: true, default: '' },
  status: { type: String, enum: ['active', 'inactive'], default: 'active' },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
  full_name: { type: String, required: true, trim: true },
  email: { type: String, required: true, lowercase: true, trim: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['super_admin', 'shop_admin', 'staff'], required: true },
  shop_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', default: null },
  is_active: { type: Boolean, default: true },
  must_change_password: { type: Boolean, default: false },
  password_changed_at: { type: Date },
  reset_password_token_hash: { type: String },
  reset_password_expires: { type: Date },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

const ProductSchema = new mongoose.Schema({
  shop_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true },
  name: { type: String, required: true, trim: true },
  brand: { type: String, trim: true, default: '' },
  category: { type: String, trim: true, default: '' },
  subcategory: { type: String, trim: true, default: '' },
  shade: { type: String, trim: true, default: '' },
  size: { type: String, trim: true, default: '' },
  unit: { type: String, default: 'Liters', trim: true },
  purchase_price: { type: Number, required: true, min: 0 },
  selling_price: { type: Number, required: true, min: 0 },
  stock: { type: Number, default: 0, min: 0 },
  minimum_stock: { type: Number, default: 5, min: 0 },
  supplier_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Supplier', default: null },
  description: { type: String, trim: true, default: '' },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

const SupplierSchema = new mongoose.Schema({
  shop_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true },
  name: { type: String, required: true, trim: true },
  phone: { type: String, trim: true, default: '' },
  email: { type: String, trim: true, lowercase: true, default: '' },
  address: { type: String, trim: true, default: '' },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

const StockTransactionSchema = new mongoose.Schema({
  shop_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true },
  product_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  type: { type: String, enum: ['IN', 'OUT', 'ADJUSTMENT'], required: true },
  quantity: { type: Number, required: true },
  note: { type: String, trim: true, default: '' },
  created_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  created_at: { type: Date, default: Date.now }
});

// Database Indexes
UserSchema.index({ email: 1 });
UserSchema.index({ shop_id: 1 });
UserSchema.index({ reset_password_token_hash: 1 });
ProductSchema.index({ shop_id: 1 });
SupplierSchema.index({ shop_id: 1 });
StockTransactionSchema.index({ shop_id: 1, created_at: -1 });
StockTransactionSchema.index({ shop_id: 1, product_id: 1 });

const Shop = mongoose.model('Shop', ShopSchema);
const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Supplier = mongoose.model('Supplier', SupplierSchema);
const StockTransaction = mongoose.model('StockTransaction', StockTransactionSchema);

// Initial Super Admin Seeding Function
async function initSuperAdmin() {
  try {
    const existingAdmin = await User.findOne({ email: 'admin@gmail.com' });
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash('123456', 12);
      await User.create({
        full_name: 'Administrator',
        email: 'admin@gmail.com',
        password: hashedPassword,
        role: 'super_admin',
        shop_id: null,
        is_active: true,
        must_change_password: true
      });
      console.log('Default Super Admin created: admin@gmail.com');
    }
  } catch (err) {
    console.error('Error initializing Super Admin:', err.message);
  }
}

// Database Connection Logic
async function connectDB() {
  let mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) {
    if (process.env.NODE_ENV === 'production') {
      console.error('MONGODB_URI environment variable is missing.');
      console.error('Please add MONGODB_URI to your Render.com Environment Variables.');
      process.exit(1);
    } else {
      console.log('MONGODB_URI is missing in dev mode. Spawning in-memory MongoDB server for preview...');
      try {
        const { MongoMemoryServer } = require('mongodb-memory-server');
        const mongoServer = await MongoMemoryServer.create();
        mongoUri = mongoServer.getUri();
      } catch (err) {
        console.error('MONGODB_URI environment variable is missing.');
        console.error('Please add MONGODB_URI to your Render.com Environment Variables.');
        process.exit(1);
      }
    }
  }

  try {
    await mongoose.connect(mongoUri);
    console.log('Successfully connected to MongoDB database.');
    await initSuperAdmin();
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  }
}

// Password Policy Checker
function validatePasswordPolicy(password) {
  if (!password || password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long.' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least 1 uppercase letter.' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least 1 lowercase letter.' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least 1 number.' };
  }
  return { valid: true };
}

// Authentication Middleware
async function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.redirect('/login');
  }

  try {
    const user = await User.findById(req.session.user._id);
    if (!user || !user.is_active) {
      req.session.destroy();
      return res.redirect('/login?error=Account is inactive or no longer exists.');
    }

    if (user.role !== 'super_admin') {
      if (!user.shop_id) {
        req.session.destroy();
        return res.redirect('/login?error=Invalid shop account configuration.');
      }
      const shop = await Shop.findById(user.shop_id);
      if (!shop || shop.status !== 'active') {
        req.session.destroy();
        return res.redirect('/login?error=Your shop account is currently inactive.');
      }
    }

    req.currentUser = user;
    next();
  } catch (err) {
    console.error('Auth Middleware Error:', err.message);
    res.redirect('/login');
  }
}

// AUTHENTICATION ROUTES

app.get('/', (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect('/app');
  }
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect('/app');
  }
  res.render('login', {
    view: 'login',
    csrfToken: req.session.csrfToken,
    error_msg: req.query.error || null,
    success_msg: req.query.success || null
  });
});

app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.render('login', {
      view: 'login',
      csrfToken: req.session.csrfToken,
      error_msg: 'Please provide both email and password.',
      success_msg: null
    });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user || !user.is_active) {
      return res.render('login', {
        view: 'login',
        csrfToken: req.session.csrfToken,
        error_msg: 'Invalid email or password.',
        success_msg: null
      });
    }

    if (user.role !== 'super_admin') {
      if (!user.shop_id) {
        return res.render('login', {
          view: 'login',
          csrfToken: req.session.csrfToken,
          error_msg: 'Invalid email or password.',
          success_msg: null
        });
      }
      const shop = await Shop.findById(user.shop_id);
      if (!shop || shop.status !== 'active') {
        return res.render('login', {
          view: 'login',
          csrfToken: req.session.csrfToken,
          error_msg: 'Your shop account is currently inactive. Please contact administrator.',
          success_msg: null
        });
      }
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render('login', {
        view: 'login',
        csrfToken: req.session.csrfToken,
        error_msg: 'Invalid email or password.',
        success_msg: null
      });
    }

    // Regenerate session to prevent session fixation
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err.message);
        return res.render('login', {
          view: 'login',
          csrfToken: req.session.csrfToken,
          error_msg: 'An error occurred during login. Please try again.',
          success_msg: null
        });
      }

      req.session.user = {
        _id: user._id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
        shop_id: user.shop_id
      };
      req.session.csrfToken = crypto.randomBytes(24).toString('hex');

      console.log(`User logged in successfully: ${user.email} (${user.role})`);

      if (user.must_change_password) {
        return res.redirect('/app?page=change_password');
      }
      res.redirect('/app?page=dashboard');
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.render('login', {
      view: 'login',
      csrfToken: req.session.csrfToken,
      error_msg: 'An unexpected error occurred. Please try again.',
      success_msg: null
    });
  }
});

app.get('/logout', (req, res) => {
  console.log(`User logged out: ${req.session.user ? req.session.user.email : 'unknown'}`);
  req.session.destroy(() => {
    res.redirect('/login?success=Logged out successfully.');
  });
});

// FORGOT PASSWORD (SUPER ADMIN ONLY)
app.get('/forgot-password', (req, res) => {
  res.render('login', {
    view: 'forgot',
    csrfToken: req.session.csrfToken,
    error_msg: null,
    success_msg: null
  });
});

app.post('/forgot-password', forgotLimiter, async (req, res) => {
  const { email } = req.body;
  const genericSuccess = 'If the Super Admin account matches this email, a password reset link has been generated.';

  if (!email) {
    return res.render('login', {
      view: 'forgot',
      csrfToken: req.session.csrfToken,
      error_msg: 'Please enter your email address.',
      success_msg: null
    });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail, role: 'super_admin' });

    if (user && user.is_active) {
      const rawToken = crypto.randomBytes(32).toString('hex');
      const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

      user.reset_password_token_hash = hashedToken;
      user.reset_password_expires = Date.now() + 15 * 60 * 1000; // 15 minutes
      await user.save();

      console.log(`[DEVELOPMENT ONLY] Super Admin Password Reset Link: /reset-password?token=${rawToken}`);
    }

    res.render('login', {
      view: 'forgot',
      csrfToken: req.session.csrfToken,
      error_msg: null,
      success_msg: genericSuccess
    });
  } catch (err) {
    console.error('Forgot password error:', err.message);
    res.render('login', {
      view: 'forgot',
      csrfToken: req.session.csrfToken,
      error_msg: null,
      success_msg: genericSuccess
    });
  }
});

// RESET PASSWORD (SUPER ADMIN)
app.get('/reset-password', (req, res) => {
  const token = req.query.token;
  if (!token) {
    return res.redirect('/forgot-password');
  }

  res.render('login', {
    view: 'reset',
    token,
    csrfToken: req.session.csrfToken,
    error_msg: null,
    success_msg: null
  });
});

app.post('/reset-password', resetLimiter, async (req, res) => {
  const { token, new_password, confirm_password } = req.body;

  if (!token) {
    return res.redirect('/forgot-password');
  }

  if (new_password !== confirm_password) {
    return res.render('login', {
      view: 'reset',
      token,
      csrfToken: req.session.csrfToken,
      error_msg: 'New password and confirmation password do not match.',
      success_msg: null
    });
  }

  const policyCheck = validatePasswordPolicy(new_password);
  if (!policyCheck.valid) {
    return res.render('login', {
      view: 'reset',
      token,
      csrfToken: req.session.csrfToken,
      error_msg: policyCheck.message,
      success_msg: null
    });
  }

  try {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      reset_password_token_hash: hashedToken,
      reset_password_expires: { $gt: Date.now() },
      role: 'super_admin'
    });

    if (!user) {
      return res.render('login', {
        view: 'reset',
        token,
        csrfToken: req.session.csrfToken,
        error_msg: 'Password reset token is invalid or has expired.',
        success_msg: null
      });
    }

    const hashedPassword = await bcrypt.hash(new_password, 12);
    user.password = hashedPassword;
    user.password_changed_at = new Date();
    user.must_change_password = false;
    user.reset_password_token_hash = undefined;
    user.reset_password_expires = undefined;
    await user.save();

    console.log(`Super Admin password reset successfully for: ${user.email}`);

    res.render('login', {
      view: 'login',
      csrfToken: req.session.csrfToken,
      error_msg: null,
      success_msg: 'Password reset successfully. Please sign in with your new password.'
    });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.render('login', {
      view: 'reset',
      token,
      csrfToken: req.session.csrfToken,
      error_msg: 'An unexpected error occurred during password reset.',
      success_msg: null
    });
  }
});

// MAIN APPLICATION HANDLER (/app)
async function appHandler(req, res) {
  const user = req.currentUser;
  let page = req.query.page || req.body.page || 'dashboard';

  // Enforce password change if mandatory
  if (user.must_change_password) {
    page = 'change_password';
  }

  let success_msg = req.query.success || null;
  let error_msg = req.query.error || null;

  // Process POST actions
  if (req.method === 'POST') {
    const action = req.body.action;

    try {
      if (action === 'change_password') {
        const { current_password, new_password, confirm_password } = req.body;

        if (!current_password || !new_password || !confirm_password) {
          error_msg = 'All password fields are required.';
        } else if (new_password !== confirm_password) {
          error_msg = 'New password and confirmation password do not match.';
        } else {
          const isMatch = await bcrypt.compare(current_password, user.password);
          if (!isMatch) {
            error_msg = 'Current password is incorrect.';
          } else if (current_password === new_password) {
            error_msg = 'New password must be different from current password.';
          } else {
            const policyCheck = validatePasswordPolicy(new_password);
            if (!policyCheck.valid) {
              error_msg = policyCheck.message;
            } else {
              const hashedPassword = await bcrypt.hash(new_password, 12);
              user.password = hashedPassword;
              user.password_changed_at = new Date();
              user.must_change_password = false;
              user.reset_password_token_hash = undefined;
              user.reset_password_expires = undefined;
              await user.save();

              console.log(`Password changed successfully for user: ${user.email}`);

              req.session.user.must_change_password = false;
              return res.redirect('/app?page=dashboard&success=' + encodeURIComponent('Password changed successfully.'));
            }
          }
        }
      }

      // SUPER ADMIN ACTIONS
      else if (action === 'create_shop' && user.role === 'super_admin') {
        const { shop_name, owner_name, email, phone, address, admin_name, admin_email, initial_password } = req.body;

        if (!shop_name || !owner_name || !email || !admin_name || !admin_email || !initial_password) {
          error_msg = 'Please fill in all required shop and admin details.';
        } else {
          const existingUser = await User.findOne({ email: admin_email.trim().toLowerCase() });
          if (existingUser) {
            error_msg = 'A user with this admin email already exists.';
          } else {
            const policyCheck = validatePasswordPolicy(initial_password);
            if (!policyCheck.valid) {
              error_msg = policyCheck.message;
            } else {
              const shop = await Shop.create({
                name: shop_name.trim(),
                owner_name: owner_name.trim(),
                email: email.trim().toLowerCase(),
                phone: phone ? phone.trim() : '',
                address: address ? address.trim() : '',
                status: 'active'
              });

              const hashedPassword = await bcrypt.hash(initial_password, 12);
              await User.create({
                full_name: admin_name.trim(),
                email: admin_email.trim().toLowerCase(),
                password: hashedPassword,
                role: 'shop_admin',
                shop_id: shop._id,
                is_active: true,
                must_change_password: true
              });

              success_msg = 'Shop and Shop Admin account created successfully. The Shop Admin must change the temporary password on first login.';
              console.log(`New shop created: ${shop.name}`);
            }
          }
        }
      }

      else if (action === 'update_shop' && user.role === 'super_admin') {
        const { shop_id, shop_name, owner_name, email, phone, address } = req.body;
        if (shop_id && mongoose.Types.ObjectId.isValid(shop_id)) {
          await Shop.findByIdAndUpdate(shop_id, {
            name: shop_name.trim(),
            owner_name: owner_name.trim(),
            email: email.trim().toLowerCase(),
            phone: phone ? phone.trim() : '',
            address: address ? address.trim() : '',
            updated_at: new Date()
          });
          success_msg = 'Shop details updated successfully.';
        }
      }

      else if (action === 'toggle_shop_status' && user.role === 'super_admin') {
        const { shop_id } = req.body;
        if (shop_id && mongoose.Types.ObjectId.isValid(shop_id)) {
          const targetShop = await Shop.findById(shop_id);
          if (targetShop) {
            targetShop.status = targetShop.status === 'active' ? 'inactive' : 'active';
            targetShop.updated_at = new Date();
            await targetShop.save();
            success_msg = `Shop ${targetShop.name} status set to ${targetShop.status}.`;
          }
        }
      }

      else if (action === 'force_password_reset') {
        const { target_user_id } = req.body;
        if (target_user_id && mongoose.Types.ObjectId.isValid(target_user_id)) {
          let targetUser = null;
          if (user.role === 'super_admin') {
            targetUser = await User.findById(target_user_id);
          } else if (user.role === 'shop_admin') {
            targetUser = await User.findOne({ _id: target_user_id, shop_id: user.shop_id, role: 'staff' });
          }

          if (targetUser) {
            const randomPart = crypto.randomBytes(4).toString('hex');
            const tempPassword = `Temp${randomPart.toUpperCase()}1!`;
            const hashedPassword = await bcrypt.hash(tempPassword, 12);

            targetUser.password = hashedPassword;
            targetUser.must_change_password = true;
            targetUser.reset_password_token_hash = undefined;
            targetUser.reset_password_expires = undefined;
            await targetUser.save();

            success_msg = `Temporary password generated for ${targetUser.email}: "${tempPassword}" — share securely and do not store publicly.`;
            console.log(`Force password reset executed for: ${targetUser.email}`);
          } else {
            error_msg = 'User not found or unauthorized.';
          }
        }
      }

      else if (action === 'toggle_user_status') {
        const { target_user_id } = req.body;
        if (target_user_id && mongoose.Types.ObjectId.isValid(target_user_id)) {
          let targetUser = null;
          if (user.role === 'super_admin') {
            targetUser = await User.findById(target_user_id);
          } else if (user.role === 'shop_admin') {
            targetUser = await User.findOne({ _id: target_user_id, shop_id: user.shop_id, role: 'staff' });
          }

          if (targetUser) {
            targetUser.is_active = !targetUser.is_active;
            await targetUser.save();
            success_msg = `User ${targetUser.email} is now ${targetUser.is_active ? 'active' : 'inactive'}.`;
          } else {
            error_msg = 'User not found or unauthorized.';
          }
        }
      }

      // SHOP ADMIN ACTIONS
      else if (action === 'create_staff' && user.role === 'shop_admin') {
        const { full_name, email, initial_password } = req.body;
        if (!full_name || !email || !initial_password) {
          error_msg = 'Please fill in all staff details.';
        } else {
          const normalizedEmail = email.trim().toLowerCase();
          const existingUser = await User.findOne({ email: normalizedEmail });
          if (existingUser) {
            error_msg = 'A user with this email address already exists.';
          } else {
            const policyCheck = validatePasswordPolicy(initial_password);
            if (!policyCheck.valid) {
              error_msg = policyCheck.message;
            } else {
              const hashedPassword = await bcrypt.hash(initial_password, 12);
              await User.create({
                full_name: full_name.trim(),
                email: normalizedEmail,
                password: hashedPassword,
                role: 'staff',
                shop_id: user.shop_id,
                is_active: true,
                must_change_password: true
              });
              success_msg = 'Staff account created successfully. Staff must change temporary password on first login.';
            }
          }
        }
      }

      else if (action === 'delete_staff' && user.role === 'shop_admin') {
        const { staff_id } = req.body;
        if (staff_id && mongoose.Types.ObjectId.isValid(staff_id)) {
          await User.deleteOne({ _id: staff_id, shop_id: user.shop_id, role: 'staff' });
          success_msg = 'Staff member removed successfully.';
        }
      }

      else if (action === 'create_product' && user.role === 'shop_admin') {
        const {
          name, brand, category, subcategory, shade, size, unit,
          purchase_price, selling_price, stock, minimum_stock, supplier_id, description
        } = req.body;

        const pPrice = parseFloat(purchase_price);
        const sPrice = parseFloat(selling_price);
        const initStock = parseInt(stock) || 0;
        const minStock = parseInt(minimum_stock) || 0;

        if (!name || isNaN(pPrice) || pPrice < 0 || isNaN(sPrice) || sPrice < 0 || initStock < 0 || minStock < 0) {
          error_msg = 'Please provide valid product name and positive prices/stock.';
        } else {
          const product = await Product.create({
            shop_id: user.shop_id,
            name: name.trim(),
            brand: brand ? brand.trim() : '',
            category: category ? category.trim() : '',
            subcategory: subcategory ? subcategory.trim() : '',
            shade: shade ? shade.trim() : '',
            size: size ? size.trim() : '',
            unit: unit ? unit.trim() : 'Liters',
            purchase_price: pPrice,
            selling_price: sPrice,
            stock: initStock,
            minimum_stock: minStock,
            supplier_id: (supplier_id && mongoose.Types.ObjectId.isValid(supplier_id)) ? supplier_id : null,
            description: description ? description.trim() : ''
          });

          if (initStock > 0) {
            await StockTransaction.create({
              shop_id: user.shop_id,
              product_id: product._id,
              type: 'IN',
              quantity: initStock,
              note: 'Initial Stock On Product Creation',
              created_by: user._id
            });
          }

          success_msg = 'Product added to inventory successfully.';
        }
      }

      else if (action === 'update_product' && user.role === 'shop_admin') {
        const {
          product_id, name, brand, category, subcategory, shade, size, unit,
          purchase_price, selling_price, minimum_stock, supplier_id, description
        } = req.body;

        if (product_id && mongoose.Types.ObjectId.isValid(product_id)) {
          const pPrice = parseFloat(purchase_price);
          const sPrice = parseFloat(selling_price);
          const minStock = parseInt(minimum_stock) || 0;

          if (!name || isNaN(pPrice) || pPrice < 0 || isNaN(sPrice) || sPrice < 0 || minStock < 0) {
            error_msg = 'Invalid product update details.';
          } else {
            await Product.findOneAndUpdate(
              { _id: product_id, shop_id: user.shop_id },
              {
                name: name.trim(),
                brand: brand ? brand.trim() : '',
                category: category ? category.trim() : '',
                subcategory: subcategory ? subcategory.trim() : '',
                shade: shade ? shade.trim() : '',
                size: size ? size.trim() : '',
                unit: unit ? unit.trim() : 'Liters',
                purchase_price: pPrice,
                selling_price: sPrice,
                minimum_stock: minStock,
                supplier_id: (supplier_id && mongoose.Types.ObjectId.isValid(supplier_id)) ? supplier_id : null,
                description: description ? description.trim() : '',
                updated_at: new Date()
              }
            );
            success_msg = 'Product updated successfully.';
          }
        }
      }

      else if (action === 'delete_product' && user.role === 'shop_admin') {
        const { product_id } = req.body;
        if (product_id && mongoose.Types.ObjectId.isValid(product_id)) {
          await Product.deleteOne({ _id: product_id, shop_id: user.shop_id });
          await StockTransaction.deleteMany({ product_id: product_id, shop_id: user.shop_id });
          success_msg = 'Product deleted from inventory.';
        }
      }

      // STOCK MANAGEMENT (SHOP ADMIN & STAFF)
      else if (action === 'stock_in') {
        const { product_id, quantity, note } = req.body;
        const qty = parseInt(quantity);

        if (!product_id || !mongoose.Types.ObjectId.isValid(product_id) || isNaN(qty) || qty <= 0) {
          error_msg = 'Please specify a valid product and a positive quantity.';
        } else {
          const updatedProduct = await Product.findOneAndUpdate(
            { _id: product_id, shop_id: user.shop_id },
            { $inc: { stock: qty }, updated_at: new Date() },
            { new: true }
          );

          if (!updatedProduct) {
            error_msg = 'Product not found in your inventory.';
          } else {
            await StockTransaction.create({
              shop_id: user.shop_id,
              product_id: updatedProduct._id,
              type: 'IN',
              quantity: qty,
              note: note ? note.trim() : 'Stock In',
              created_by: user._id
            });
            success_msg = `Added ${qty} units to ${updatedProduct.name}. New Stock: ${updatedProduct.stock}.`;
          }
        }
      }

      else if (action === 'stock_out') {
        const { product_id, quantity, note } = req.body;
        const qty = parseInt(quantity);

        if (!product_id || !mongoose.Types.ObjectId.isValid(product_id) || isNaN(qty) || qty <= 0) {
          error_msg = 'Please specify a valid product and positive quantity.';
        } else {
          const product = await Product.findOne({ _id: product_id, shop_id: user.shop_id });
          if (!product) {
            error_msg = 'Product not found in your inventory.';
          } else if (product.stock < qty) {
            error_msg = `Insufficient stock available (${product.stock} units available, requested ${qty}).`;
          } else {
            const updatedProduct = await Product.findOneAndUpdate(
              { _id: product_id, shop_id: user.shop_id, stock: { $gte: qty } },
              { $inc: { stock: -qty }, updated_at: new Date() },
              { new: true }
            );

            if (!updatedProduct) {
              error_msg = 'Failed to process Stock OUT due to concurrent modification or low stock.';
            } else {
              await StockTransaction.create({
                shop_id: user.shop_id,
                product_id: updatedProduct._id,
                type: 'OUT',
                quantity: qty,
                note: note ? note.trim() : 'Stock Out',
                created_by: user._id
              });
              success_msg = `Deducted ${qty} units from ${updatedProduct.name}. Remaining Stock: ${updatedProduct.stock}.`;
            }
          }
        }
      }

      else if (action === 'stock_adjustment' && user.role === 'shop_admin') {
        const { product_id, new_stock, note } = req.body;
        const newQty = parseInt(new_stock);

        if (!product_id || !mongoose.Types.ObjectId.isValid(product_id) || isNaN(newQty) || newQty < 0) {
          error_msg = 'Please specify a valid new stock quantity (>= 0).';
        } else {
          const product = await Product.findOne({ _id: product_id, shop_id: user.shop_id });
          if (!product) {
            error_msg = 'Product not found.';
          } else {
            const diff = newQty - product.stock;
            product.stock = newQty;
            product.updated_at = new Date();
            await product.save();

            await StockTransaction.create({
              shop_id: user.shop_id,
              product_id: product._id,
              type: 'ADJUSTMENT',
              quantity: diff,
              note: note ? note.trim() : `Manual Adjustment to ${newQty}`,
              created_by: user._id
            });

            success_msg = `Stock adjusted for ${product.name} to ${newQty} units.`;
          }
        }
      }

      // SUPPLIERS
      else if (action === 'create_supplier' && user.role === 'shop_admin') {
        const { name, phone, email, address } = req.body;
        if (!name) {
          error_msg = 'Supplier name is required.';
        } else {
          await Supplier.create({
            shop_id: user.shop_id,
            name: name.trim(),
            phone: phone ? phone.trim() : '',
            email: email ? email.trim().toLowerCase() : '',
            address: address ? address.trim() : ''
          });
          success_msg = 'Supplier created successfully.';
        }
      }

      else if (action === 'update_supplier' && user.role === 'shop_admin') {
        const { supplier_id, name, phone, email, address } = req.body;
        if (supplier_id && mongoose.Types.ObjectId.isValid(supplier_id)) {
          await Supplier.findOneAndUpdate(
            { _id: supplier_id, shop_id: user.shop_id },
            {
              name: name.trim(),
              phone: phone ? phone.trim() : '',
              email: email ? email.trim().toLowerCase() : '',
              address: address ? address.trim() : '',
              updated_at: new Date()
            }
          );
          success_msg = 'Supplier details updated successfully.';
        }
      }

      else if (action === 'delete_supplier' && user.role === 'shop_admin') {
        const { supplier_id } = req.body;
        if (supplier_id && mongoose.Types.ObjectId.isValid(supplier_id)) {
          await Supplier.deleteOne({ _id: supplier_id, shop_id: user.shop_id });
          await Product.updateMany({ supplier_id }, { supplier_id: null });
          success_msg = 'Supplier deleted successfully.';
        }
      }
    } catch (err) {
      console.error(`Error processing action "${action}":`, err.message);
      error_msg = 'An error occurred while processing your request.';
    }
  }

  // FETCH DATA FOR VIEW RENDERING
  try {
    let shop = null;
    let products = [];
    let suppliers = [];
    let staffs = [];
    let shops = [];
    let shop_admins = [];
    let transactions = [];
    let low_stock_products = [];
    let out_of_stock_products = [];
    let dashboard_stats = {};
    let selected_product = null;
    let product_transactions = [];

    if (user.role === 'super_admin') {
      shops = await Shop.find().sort({ created_at: -1 });
      shop_admins = await User.find({ role: 'shop_admin' }).populate('shop_id');
      const totalShops = shops.length;
      const activeShops = shops.filter(s => s.status === 'active').length;
      const inactiveShops = shops.filter(s => s.status === 'inactive').length;
      const totalProductsCount = await Product.countDocuments();
      const totalUsersCount = await User.countDocuments();

      const allProducts = await Product.find();
      const totalValue = allProducts.reduce((sum, p) => sum + (p.selling_price * p.stock), 0);

      dashboard_stats = {
        total_shops: totalShops,
        active_shops: activeShops,
        inactive_shops: inactiveShops,
        total_products: totalProductsCount,
        total_users: totalUsersCount,
        total_inventory_value: totalValue
      };

      if (req.query.shop_id && mongoose.Types.ObjectId.isValid(req.query.shop_id)) {
        shop = await Shop.findById(req.query.shop_id);
        products = await Product.find({ shop_id: req.query.shop_id }).populate('supplier_id').sort({ name: 1 });
      }
    } else {
      shop = await Shop.findById(user.shop_id);
      products = await Product.find({ shop_id: user.shop_id }).populate('supplier_id').sort({ name: 1 });
      suppliers = await Supplier.find({ shop_id: user.shop_id }).sort({ name: 1 });
      staffs = await User.find({ shop_id: user.shop_id, role: 'staff' }).sort({ created_at: -1 });
      transactions = await StockTransaction.find({ shop_id: user.shop_id })
        .populate('product_id')
        .populate('created_by')
        .sort({ created_at: -1 })
        .limit(100);

      // Filtering search or brand/category if provided
      if (req.query.search) {
        const regex = new RegExp(req.query.search, 'i');
        products = products.filter(p =>
          regex.test(p.name) || regex.test(p.brand) || regex.test(p.category) || regex.test(p.shade) || regex.test(p.size)
        );
      }
      if (req.query.brand) {
        products = products.filter(p => p.brand.toLowerCase() === req.query.brand.toLowerCase());
      }
      if (req.query.category) {
        products = products.filter(p => p.category.toLowerCase() === req.query.category.toLowerCase());
      }

      low_stock_products = products.filter(p => p.stock <= p.minimum_stock && p.stock > 0);
      out_of_stock_products = products.filter(p => p.stock === 0);

      const totalStockUnits = products.reduce((sum, p) => sum + p.stock, 0);
      const inventoryVal = products.reduce((sum, p) => sum + (p.selling_price * p.stock), 0);

      dashboard_stats = {
        total_products: products.length,
        total_stock_units: totalStockUnits,
        inventory_value: inventoryVal,
        low_stock_count: low_stock_products.length,
        out_of_stock_count: out_of_stock_products.length,
        suppliers_count: suppliers.length,
        staff_count: staffs.length
      };

      if (req.query.edit_product_id && mongoose.Types.ObjectId.isValid(req.query.edit_product_id)) {
        selected_product = await Product.findOne({ _id: req.query.edit_product_id, shop_id: user.shop_id });
      }

      if (req.query.history_product_id && mongoose.Types.ObjectId.isValid(req.query.history_product_id)) {
        product_transactions = await StockTransaction.find({
          shop_id: user.shop_id,
          product_id: req.query.history_product_id
        }).populate('product_id').populate('created_by').sort({ created_at: -1 });
      }
    }

    res.render('app', {
      user,
      page,
      success_msg,
      error_msg,
      csrfToken: req.session.csrfToken,
      shop,
      products,
      suppliers,
      staffs,
      shops,
      shop_admins,
      transactions,
      low_stock_products,
      out_of_stock_products,
      dashboard_stats,
      selected_product,
      product_transactions,
      query: req.query
    });
  } catch (err) {
    console.error('Render App Error:', err.message);
    res.status(500).send('An unexpected error occurred while loading application.');
  }
}

app.get('/app', requireAuth, appHandler);
app.post('/app', requireAuth, appHandler);

// START SERVER AND CONNECT DATABASE
connectDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running securely on port ${PORT}`);
  });
});
