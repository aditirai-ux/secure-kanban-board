import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  // TODO: verify the token exists and add the user data to the request object
  const authHeader = req.headers['authorization']; // Get the authorization header
  if (authHeader) {
    const token = authHeader.split(' ')[1]; // Extract the token from the authorization header
    const secretKey = process.env.JWT_SECRET_KEY || ''; // Get the secret key from the environment variables
// Verify the token and add the user data to the request object
    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        return res.sendStatus(403); // token is invalid
      }
      req.user = user as JwtPayload; // Attach the user information to the request object
      return next(); //calls next middleware function
    });
  } else {
    res.sendStatus(401); // token is missing or no authorization header
  }
};
