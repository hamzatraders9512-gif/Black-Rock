import { MongoClient } from 'mongodb';

const uri = process.env.MONGODB_URI;
if (!uri) {
  console.warn('MONGODB_URI is not set. DB operations will fail.');
}

let client;
let clientPromise;

export async function getClient() {
  if (!uri) throw new Error('Missing MONGODB_URI');
  if (!clientPromise) {
    client = new MongoClient(uri);
    clientPromise = client.connect();
  }
  await clientPromise;
  return client;
}

export async function getDb(dbName) {
  const c = await getClient();
  // If connection string includes a default database, .db() without arg returns it, else use provided or 'test'
  return c.db(dbName);
}
