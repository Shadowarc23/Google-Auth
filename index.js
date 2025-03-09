const express = require('express');
const session = require('express-session');
const { OAuth2Client } = require('google-auth-library');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = 3000;

// Initialize Google OAuth Client
const client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// Middleware for handling sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(express.static(path.join(__dirname, 'public')));

// Set EJS as the template engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Home Route
app.get('/', (req, res) => {
  if (req.session.user) {
    res.render('profile', { user: req.session.user });
  } else {
    res.render('index');
  }
});

// Google Login Route
app.get('/auth/google', (req, res) => {
  const url = client.generateAuthUrl({
    access_type: 'offline',
    scope: ['profile', 'email'],
  });
  res.redirect(url);
});

// Google OAuth Callback Route
app.get('/auth/google/callback', async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.status(400).send('Invalid request. No authorization code provided.');
  }

  try {
    // Exchange authorization code for access token
    const { tokens } = await client.getToken(code);

    // Verify the token and get user information
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    // Save user info in session
    req.session.user = {
      name: payload.name,
      email: payload.email,
      picture: payload.picture,
    };

    res.redirect('/');
  } catch (error) {
    console.error('Error during Google OAuth callback:', error);
    res.status(500).send('Authentication failed.');
  }
});

// Logout Route
app.get('/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Failed to logout.');
    }
    res.redirect('/');
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});