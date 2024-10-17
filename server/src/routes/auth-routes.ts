import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export const login = async (req: Request, res: Response) => {
  // TODO: If the user exists and the password is correct, return a JWT token
  const { username, password } = req.body; // Get the username and password from the request body
  const user = await User.findOne({ // Find the user by username
    where: { username },
  });

  if (!user) {
    return res.status(401).json({message: 'Authentication Failed'}); // User not found
  }
  const isPasswordValid = await bcrypt.compare(password, user.password); // Compare the password with the hashed password
  if (!isPasswordValid) {
    return res.status(401).json({message: 'Authentication Failed'}); // Password is invalid
  }

  // Get the secret key from the environment variables
  const secretKey = process.env.JWT_SECRET_KEY || ''; 
  // Create a JWT token with an expiration
  const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' }); 
  return res.status(200).json({ token }); // Return the JWT token
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
