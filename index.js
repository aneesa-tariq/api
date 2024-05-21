import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

//database 
const users = [
  { id: 1, email: 'user1@example.com', password: '$2b$10$K3YBXXa2bMMsKGZvSvWbCuH/0r1dwnrHgHPu3dz2lBPQaTx1DQUlC' }, // Password is "password1"
  { id: 2, email: 'user2@example.com', password: '$2b$10$dIsHdU8F3tE5Jg.ZNeSdqecK83/Vho.UlExJngSRQeh/0iwLysV7S' }, // Password is "password2"
];

const app = express();
const PORT = 3000;

// Middleware to parse JSON requests
app.use(bodyParser.json());

// Route for user login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  const user = Users.find(user => user.email === email);

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  // Compare provided password with stored hashed password
  bcrypt.compare(password, user.password, (err, result) => {
    if (err || !result) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, 'secret', { expiresIn: '1h' });

    // Return the token to the client
    res.json({ token });
  });
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(403).json({ message: 'Token not provided' });
  }

  // Verify the token using the secret key
  jwt.verify(token, 'secret', (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Failed to authenticate token' });
    }

    // Attach decoded user information to the request object
    req.user = decoded;
    next();
  });
}

// Example protected route
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'You have access to this protected route', user: req.user });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
