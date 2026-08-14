require('dotenv').config();
const mongoose = require('mongoose');

async function testConnection() {
    try {
        console.log('🔍 Testing MongoDB Connection...');
        console.log('📌 Username: mikunkumar242_db_user');
        
        await mongoose.connect(process.env.MONGODB_URI);
        
        console.log('✅ Connection Successful!');
        console.log('📊 Database:', mongoose.connection.db.databaseName);
        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error.message);
        console.log('\n💡 Fix Checklist:');
        console.log('   1. Check username in .env file');
        console.log('   2. Check password in .env file');
        console.log('   3. Password should NOT have special characters (@, #, $, etc.)');
        console.log('   4. MongoDB Atlas Network Access: 0.0.0.0/0');
        console.log('   5. Try simple password like: mypassword123');
        process.exit(1);
    }
}

testConnection();