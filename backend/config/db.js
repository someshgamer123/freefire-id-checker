const mongoose = require('mongoose');
const dns = require('dns');

// 🛡️ Force Google DNS — fixes "querySrv ENOTFOUND" on hosting
try {
    dns.setServers(['8.8.8.8', '8.8.4.4', '1.1.1.1']);
} catch(e) {
    console.warn('⚠️ Could not set custom DNS servers:', e.message);
}

let isConnected = false;

const connectDB = async () => {
    try {
        let uri = (process.env.MONGODB_URI || process.env.MONGO_URI || '').trim();
        uri = uri.replace(/^["']+|["']+$/g, '').trim();
        uri = uri.replace(/[\r\n\t]/g, '');

        const maskedUri = uri.replace(/:([^:@]+)@/, ':****@');
        console.log('═══════════════════════════════════════');
        console.log('🔍 MONGODB_URI exists:', !!process.env.MONGODB_URI);
        console.log('🔍 URI length:', uri.length);
        console.log('🔍 Masked URI:', maskedUri);
        console.log('🔍 Starts with mongodb+srv:', uri.startsWith('mongodb+srv://'));
        console.log('🔍 Starts with mongodb://:', uri.startsWith('mongodb://'));

        const userMatch = uri.match(/mongodb\+srv:\/\/([^:]+):/);
        if (userMatch) console.log('🔍 Username in URI:', userMatch[1]);
        console.log('═══════════════════════════════════════');

        if (!uri) {
            console.error('❌ MONGODB_URI is empty!');
            process.exit(1);
        }

        if (!uri.startsWith('mongodb://') && !uri.startsWith('mongodb+srv://')) {
            console.error('❌ MONGODB_URI invalid scheme!');
            process.exit(1);
        }

        mongoose.set('bufferCommands', false);
        mongoose.set('bufferTimeoutMS', 5000);
        mongoose.set('strictQuery', false);

        console.log('⏳ Connecting to MongoDB...');

        const conn = await mongoose.connect(uri, {
            serverSelectionTimeoutMS: 15000,
            socketTimeoutMS: 45000,
            maxPoolSize: 10,
        });

        isConnected = true;
        console.log('═══════════════════════════════════════');
        console.log(`✅ MongoDB Connected Successfully!`);
        console.log(`📊 Host: ${conn.connection.host}`);
        console.log(`📊 Database: ${conn.connection.name}`);
        console.log('═══════════════════════════════════════');

        mongoose.connection.on('disconnected', () => {
            console.warn('⚠️ MongoDB disconnected');
            isConnected = false;
        });

        mongoose.connection.on('reconnected', () => {
            console.log('✅ MongoDB reconnected');
            isConnected = true;
        });

        return conn;

    } catch (error) {
        console.error('═══════════════════════════════════════');
        console.error(`❌ MongoDB Connection FAILED`);
        console.error(`📌 Error: ${error.message}`);
        console.error('═══════════════════════════════════════');
        
        if (error.message.includes('bad auth')) {
            console.error('🔐 AUTH FAILED — Password galat hai!');
        } else if (error.message.includes('ENOTFOUND')) {
            console.error('🌐 DNS FAILED — Internet ya cluster URL check karo');
        } else if (error.message.includes('timeout')) {
            console.error('⏱️ TIMEOUT — Network Access check karo');
        }
        
        console.error('═══════════════════════════════════════');
        process.exit(1);
    }
};

module.exports = connectDB;
module.exports.isDBConnected = () => isConnected;
