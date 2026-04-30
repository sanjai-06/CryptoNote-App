const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  icon: { type: String, default: '📁' },
  color: { type: String, default: '#8B5CF6' }, // Default purple color
}, { timestamps: true });

// Ensure unique category names per user
categorySchema.index({ userId: 1, name: 1 }, { unique: true });

module.exports = mongoose.model('Category', categorySchema);
