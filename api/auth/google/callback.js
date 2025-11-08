import jwt from 'jsonwebtoken';
import { getDb } from '../../lib/mongodb.js';
import { addSecurityHeaders } from '../../middleware/security.js';

export default async function handler(req, res) {
  // Add security headers
  addSecurityHeaders(req, res);
  try {
    const urlParams = req.query && Object.keys(req.query).length ? req.query : (req.url.split('?')[1] ? Object.fromEntries(new URLSearchParams(req.url.split('?')[1])) : {});
    const code = urlParams.code;
    if (!code) return res.status(400).send('Missing code');

    const params = new URLSearchParams({
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: process.env.GOOGLE_CALLBACK_URL,
      grant_type: 'authorization_code'
    });

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });

    const tokenData = await tokenRes.json();
    if (tokenData.error) {
      console.error('Token error:', tokenData);
      return res.status(400).send(JSON.stringify(tokenData));
    }

    const idToken = tokenData.id_token;
    if (!idToken) return res.status(400).send('No id_token returned');

    const parts = idToken.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());

    const userPayload = {
      email: payload.email,
      firstName: payload.given_name || (payload.name ? payload.name.split(' ')[0] : ''),
      lastName: payload.family_name || (payload.name ? payload.name.split(' ').slice(1).join(' ') : ''),
      picture: payload.picture || '',
      googleId: payload.sub || ''
    };

    // Persist user to MongoDB Atlas (upsert)
    let userDoc = null;
    try {
      const db = await getDb();
      const users = db.collection('users');
      const now = new Date();
      const result = await users.findOneAndUpdate(
        { email: userPayload.email },
        {
          $set: {
            firstName: userPayload.firstName,
            lastName: userPayload.lastName,
            profilePicture: userPayload.picture,
            googleId: userPayload.googleId,
            updatedAt: now
          },
          $setOnInsert: { createdAt: now }
        },
        { upsert: true, returnDocument: 'after' }
      );
      userDoc = result.value;
    } catch (dbErr) {
      console.error('DB upsert error:', dbErr);
      // Continue without DB: fall back to jwt-only session
    }

    const sessionUser = userDoc ? { id: userDoc._id.toString(), email: userDoc.email, firstName: userDoc.firstName, lastName: userDoc.lastName, profilePicture: userDoc.profilePicture } : { email: userPayload.email, firstName: userPayload.firstName, lastName: userPayload.lastName, profilePicture: userPayload.picture };

    const sessionToken = jwt.sign({ user: sessionUser }, process.env.SESSION_SECRET, { expiresIn: '7d' });

    const cookieParts = [
      `br_session=${sessionToken}`,
      'HttpOnly',
      'Path=/',
      'SameSite=Lax'
    ];
    if (process.env.NODE_ENV === 'production') cookieParts.push('Secure');
    cookieParts.push('Max-Age=' + 7 * 24 * 60 * 60);

    res.setHeader('Set-Cookie', cookieParts.join('; '));
    res.writeHead(302, { Location: '/dashboard' });
    res.end();
  } catch (err) {
    console.error('Callback error:', err);
    res.status(500).send('Authentication error');
  }
}
