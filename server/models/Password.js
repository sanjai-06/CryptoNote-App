const mongoose = require('mongoose');

const passwordSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  website: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }, // Later we’ll encrypt this
  category: { type: String, default: 'Personal' },
}, { timestamps: true });

module.exports = mongoose.model('Password', passwordSchema);
