// server/src/models/User.ts
// Zero-knowledge user model – stores ONLY the auth_key_hash, never the master password
import mongoose, { Schema, Document } from 'mongoose';

export interface IUser extends Document {
    email: string;
    auth_key_hash: string;  // SHA-256 of device_key – master password never stored
    device_ids: string[];
    created_at: Date;
    last_login?: Date;
    is_active: boolean;
}

const UserSchema = new Schema<IUser>({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    auth_key_hash: { type: String, required: true },         // not a password hash – auth key hash
    device_ids: { type: [String], default: [] },
    created_at: { type: Date, default: Date.now },
    last_login: { type: Date },
    is_active: { type: Boolean, default: true },
}, { versionKey: false });

// Never expose auth_key_hash in JSON responses
UserSchema.set('toJSON', {
    transform: (_doc, ret) => {
        delete ret.auth_key_hash;
        return ret;
    }
});

export const User = mongoose.model<IUser>('User', UserSchema);
