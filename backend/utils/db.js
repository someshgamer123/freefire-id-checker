const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        // 🛡️ Try both MONGODB_URI and MONGO_URI (fallback)
        const uri = process.env.MONGODB_URI || process.env.MONGO_URI;
        
        if (!uri) {
            console.error('❌ Neither MONGODB_URI nor MONGO_URI is defined in environment variables');
            console.error('👉 Please add MONGODB_URI to your hosting environment variables');
            console.error('👉 Example: MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/dbname');
            process.exit(1);
        }
        
        const conn = await mongoose.connect(uri, {
            serverSelectionTimeoutMS: 10000,
        });
        console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
        console.log(`📊 Database: ${conn.connection.name}`);
        return conn;
    } catch (error) {
        console.error(`❌ MongoDB Connection Error: ${error.message}`);
        console.log('🔄 Retrying connection in 5 seconds...');
        setTimeout(connectDB, 5000);
    }
};

module.exports = connectDB;
