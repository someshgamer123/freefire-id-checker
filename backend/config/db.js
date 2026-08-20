const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        if (!process.env.MONGODB_URI) {
            console.error('❌ MONGODB_URI is not defined in .env file');
            process.exit(1);
        }
        const conn = await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 10000,
        });
        console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
        return conn;
    } catch (error) {
        console.error(`❌ MongoDB Connection Error: ${error.message}`);
        console.log('🔄 Retrying connection in 5 seconds...');
        setTimeout(connectDB, 5000);
    }
};

module.exports = connectDB;
