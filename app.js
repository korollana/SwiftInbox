const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const app = express();
const port = 3000;
const uuid = require('uuid');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

app.use(bodyParser.json());

const db = mysql.createConnection({
  host: "127.0.0.1",
  user: "root",
  password: "12345678",
  database: 'swiftinboxdb',
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL');
});

app.post('/register', async (req, res) => {
  const { username, rawPassword, first_name, last_name, phone_number } = req.body;

  if (!username || !rawPassword || !first_name || !last_name || !phone_number) {
    return res.status(400).json({ message: 'Please provide all the required information.' });
  }

  // Validate that the password is an 8-digit number
  const passwordRegex = /^\d{8}$/;
  if (!passwordRegex.test(rawPassword)) {
    return res.status(400).json({ message: 'Password must be an 8-digit number.' });
  }

  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(rawPassword, saltRounds);
  const uniqueEmail = `${uuidv4().slice(0, 10)}@swiftinbox.com`;

  const query = 'INSERT INTO users (username, password, email, first_name, last_name, phone_number) VALUES (?, ?, ?, ?, ?, ?)';

  db.query(query, [username, hashedPassword, uniqueEmail, first_name, last_name, `+${phone_number}`], (err, result) => {
    if (err) {
      console.error('SQL error:', err);
      res.status(500).json({ message: 'Server error' });
      return;
    }

    res.status(201).json({ message: 'User registered successfully', email: uniqueEmail });
  });
});

app.post('/login', (req, res) => {
  const { email, rawPassword } = req.body;

  if (!email || !rawPassword) {
    return res.status(400).json({ message: 'Please provide email and password.' });
  }

  const query = 'SELECT * FROM users WHERE email = ?';

  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error('SQL error:', err);
      res.status(500).json({ message: 'Server error' });
      return;
    }

    if (results.length === 0) {
      res.status(401).json({ message: 'Authentication failed. User not found.' });
      return;
    }

    const user = results[0];
    const passwordMatch = await bcrypt.compare(rawPassword, user.password);

    if (passwordMatch) {
      res.status(200).json({ message: 'Authentication successful' });
    } else {
      res.status(401).json({ message: 'Authentication failed. Incorrect password.' });
    }
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});