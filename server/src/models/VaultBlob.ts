// server/src/models/VaultBlob.ts
// Encrypted vault blob model – server stores this opaquely and cannot read contents
import mongoose, { Schema, Document } from 'mongoose';

export interface IVaultBlob extends Document {
    user_id: string;
    device_id: string;
    version: number;          // monotonic version counter for conflict resolution
    timestamp: number;        // unix epoch ms
    encrypted_vault: {        // XChaCha20-Poly1305 encrypted payload
        nonce: string;
        ciphertext: string;
        algorithm: string;
    };
    hmac: string;             // HMAC-SHA256 of key fields, protects integrity
    sequence: number;         // monotonic sequence for replay protection
    size_bytes: number;
    created_at: Date;
    updated_at: Date;
}

const EncryptedDataSchema = new Schema({
    nonce: { type: String, required: true },
    ciphertext: { type: String, required: true },
    algorithm: { type: String, required: true, default: 'XChaCha20-Poly1305' },
}, { _id: false });

const VaultBlobSchema = new Schema<IVaultBlob>({
    user_id: { type: String, required: true, index: true },
    device_id: { type: String, required: true },
    version: { type: Number, required: true, default: 1 },
    timestamp: { type: Number, required: true },
    encrypted_vault: { type: EncryptedDataSchema, required: true },
    hmac: { type: String, required: true },
    sequence: { type: Number, required: true },
    size_bytes: { type: Number, required: true },
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
}, { versionKey: false });

VaultBlobSchema.index({ user_id: 1, version: -1 });

export const VaultBlob = mongoose.model<IVaultBlob>('VaultBlob', VaultBlobSchema);
