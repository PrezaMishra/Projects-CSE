const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

// Serve static files
//app.use(express.static(path.join(__dirname, 'assets'))); OR
app.use('/css', express.static(path.join(__dirname, 'assets', 'css')));
app.use('/js', express.static(path.join(__dirname, 'assets', 'js')));
app.use('/images', express.static(path.join(__dirname, 'assets', 'images')));


// Dynamically serve HTML files from the root folder
const htmlFilesRoot = fs.readdirSync(__dirname).filter(file => file.endsWith('.html') && file !== 'details');
htmlFilesRoot.forEach(file => {
  const routePath = '/' + file.replace('.html', ''); // Create a route like '/index', '/loginpages', etc.
  app.get(routePath, (req, res) => {
    res.sendFile(path.join(__dirname, file)); // Serve the respective HTML file
  });
});

function serveHtmlFilesFromDirectory(dirPath, routePrefix = '') {
  const files = fs.readdirSync(dirPath);

  files.forEach(file => {
    const fullPath = path.join(dirPath, file);
    let routePath = path.join(routePrefix, file.replace('.html', ''));
    routePath = routePath.replace(/\\/g, '/');
    if (fs.statSync(fullPath).isDirectory()) {
      // Recursively call for subdirectories
      serveHtmlFilesFromDirectory(fullPath, routePath);
    } else if (file.endsWith('.html')) {
      // Serve the HTML file
      app.get(routePath, (req, res) => {
        res.sendFile(fullPath); // Serve the HTML file
      });
    }
  });
}
serveHtmlFilesFromDirectory(path.join(__dirname, 'details'), '/details');
serveHtmlFilesFromDirectory(path.join(__dirname, 'adminafterlogin'), '/adminafterlogin');

// Middleware
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || "mongodb://localhost:27017/zaika_users", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("Failed to connect to MongoDB:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Signup Route
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'signup.html'));
});

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists. Please login." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error creating user", error });
  }
});

// Login Route
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html')); 
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: "1h" });

    await new ActivityLog({ userId: user._id, username: user.username, action: 'login' }).save();

    res.status(200).json({ message: "✅ Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Error during login", error });
  }
});
// /logout route
app.post('/logout', async (req, res) => {
  const { userId, username } = req.body;

  if (!userId || !username) {
    return res.status(400).json({ message: "User ID and username are required" });
  }

  try {
    // Log the logout event
    await new ActivityLog({ userId, username, action: 'logout' }).save();
    res.status(200).json({ message: " ✅ Logout successful" });
  } catch (error) {
    res.status(500).json({ message: "Error during logout", error });
  }
});


//ADMIN LOGIN
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { strict: true });

const Admin = mongoose.model('Admin', adminSchema);
// Admin Login and Signup Page
app.get('/adminlogin', (req, res) => {
  res.sendFile(path.join(__dirname, 'adminlogin.html'));
});

// Admin Login and Signup Logic
app.post('/adminlogin', async (req, res) => {
  const { email, password, action } = req.body;

  if (!email || !password || !action) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    if (action === "adminsignup") {
      // Check if admin already exists
      const existingAdmin = await Admin.findOne({ email });
      if (existingAdmin) {
        return res.status(409).json({ message: "Admin already exists. Please login." });
      }

      // Hash the password and save admin
      const hashedPassword = await bcrypt.hash(password, 10);
      const newAdmin = new Admin({ email, password: hashedPassword });
      await newAdmin.save();
      return res.status(201).json({ message: " ✅ Admin registered successfully" });
    } else if (action === "adminlogin") {
      // Admin login logic
      const admin = await Admin.findOne({ email });
      if (!admin) {
        return res.status(404).json({ message: "Admin not found" });
      }

      const isPasswordValid = await bcrypt.compare(password, admin.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      const token = jwt.sign({ id: admin._id, email: admin.email }, JWT_SECRET, { expiresIn: "1h" });
      return res.status(200).json({ message: " ✅ Login successful", token });
    } else {
      return res.status(400).json({ message: "Invalid action" });
    }
  } catch (error) {
    console.error("Error handling admin login/signup:", error);
    res.status(500).json({ message: "Error handling admin login/signup", error });
  }
});
const activityLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: { type: String, required: true },
  action: { type: String, enum: ['login', 'logout'], required: true },
  timestamp: { type: Date, default: Date.now },
});

const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

//  /admin/users route
app.get('/admin/users', async (req, res) => {
  try {
    const users = await User.find({}, 'username email').exec();
    const activityLogs = await ActivityLog.find().sort({ timestamp: 1 }).exec();

    const result = users.map(user => {
      const logs = activityLogs.filter(log => log.userId.toString() === user._id.toString());

      let hasImproperLogout = false;
      const activity = [];
      for (let i = 0; i < logs.length; i++) {
        activity.push({ action: logs[i].action, timestamp: logs[i].timestamp });
        if (logs[i].action === 'login' && (!logs[i + 1] || logs[i + 1].action !== 'logout')) {
          hasImproperLogout = true;
        }
      }

      return {
        username: user.username,
        email: user.email,
        activity,
        status: hasImproperLogout ? 'Improper logout detected' : 'All good',
      };
    });

    res.status(200).json(result);
  } catch (error) {
    res.status(500).json({ message: "Error fetching user data", error });
  }
});



// map
const FoodItem = require('./models/FoodItem');
app.get('/get-food-items', async (req, res) => {
  const { lat, lng } = req.query;

  if (!lat || !lng) {
    return res.status(400).json({ error: 'Latitude and longitude are required' });
  }

  try {
    const fooditems = await FoodItem.find({
      /*location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(lng), parseFloat(lat)] // [longitude, latitude]
          },
          //$maxDistance: 5000 // 5 km
        },
      },*/
    });
    res.json(fooditems);
  } catch (error) {
    console.error('Error fetching food items:', error);
    res.status(500).json({ error: 'Error fetching food items' });
  }
});

// Map route to add markers
app.post('/admin/add-marker', async (req, res) => {
  const { name, description, lat, lng } = req.body;

  if (!name || !description || !lat || !lng) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const newMarker = new FoodItem({
      name,
      description,
      location: {
        type: 'Point',
        coordinates: [parseFloat(lng), parseFloat(lat)],
      },
    });
    await newMarker.save();
    res.status(201).json({ message: 'Marker added successfully', marker: newMarker });
  } catch (error) {
    console.error('Error adding marker:', error);
    res.status(500).json({ error: 'Error adding marker' });
  }
});
// Map route to delete markers
app.delete('/admin/delete-marker/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const deletedMarker = await FoodItem.findByIdAndDelete(id);
    if (!deletedMarker) {
      return res.status(404).json({ error: 'Marker not found' });
    }
    res.status(200).json({ message: 'Marker deleted successfully' });
  } catch (error) {
    console.error('Error deleting marker:', error);
    res.status(500).json({ error: 'Error deleting marker' });
  }
});
// Map route to update markers
app.put('/admin/update-marker/:id', async (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;

  try {
    const updatedMarker = await FoodItem.findByIdAndUpdate(
      id,
      { name, description },
      { new: true }
    );
    if (!updatedMarker) {
      return res.status(404).json({ error: 'Marker not found' });
    }
    res.status(200).json({ message: 'Marker updated successfully', marker: updatedMarker });
  } catch (error) {
    console.error('Error updating marker:', error);
    res.status(500).json({ error: 'Error updating marker' });
  }
});


//AFTERLOGIN
app.get('/afterlogin', (req, res) => {
  res.sendFile(path.join(__dirname, 'afterlogin.html'));
});
//Admin afterlogin
app.get('/adminafterlogin', (req, res) => {
  res.sendFile(path.join(__dirname, 'adminafterlogin.html'));
});


//getting files in details folder
/*app.get('/udupi.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'details/udupi.html'));
});*/

// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
