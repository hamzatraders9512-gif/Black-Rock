// Debug endpoint disabled in production - removed sensitive output
export default function handler(req, res) {
  res.status(404).json({ message: 'Not found' });
}
