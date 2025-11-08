import jwt from 'jsonwebtoken';
import { getDb } from './lib/mongodb.js';

export default async function handler(req, res) {
  const cookie = req.headers.cookie || '';
  const match = cookie.split(';').map(c=>c.trim()).find(c => c.startsWith('br_session='));
  if (!match) return res.json({ isAuthenticated: false });

  const token = match.split('=')[1];
  try {
    const decoded = jwt.verify(token, process.env.SESSION_SECRET);
    const sessionUser = decoded.user;

    // If we have DB, fetch fresh profile
    try {
      const db = await getDb();
      const users = db.collection('users');
      const doc = await users.findOne({ email: sessionUser.email });
      if (doc) {
        return res.json({ isAuthenticated: true, user: { firstName: doc.firstName, lastName: doc.lastName, email: doc.email, profilePicture: doc.profilePicture } });
      }
    } catch (dbErr) {
      // ignore DB errors and return session user
      console.error('Status DB error:', dbErr);
    }

    res.json({ isAuthenticated: true, user: sessionUser });
  } catch (err) {
    res.json({ isAuthenticated: false });
  }
}
