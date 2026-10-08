// fix-daily-data.js
// यह स्क्रिप्ट dailyVisits/dailyClaims को साफ करके आज की तारीख में डाल देगी
// Command: node fix-daily-data.js

require('dotenv').config();
const mongoose = require('mongoose');

const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/free_redeemcode';

async function fixData() {
    try {
        console.log('🔄 MongoDB से कनेक्ट हो रहा है...');
        await mongoose.connect(MONGO_URI);
        console.log('✅ Connected to MongoDB');

        const db = mongoose.connection.db;
        const linkCollection = db.collection('links');
        const statsCollection = db.collection('stats');

        const now = new Date();
        const istOffset = 5.5 * 60 * 60 * 1000;
        const istNow = new Date(now.getTime() + istOffset);
        const today = istNow.toISOString().split('T')[0];

        console.log(`\n📅 आज की तारीख (IST): ${today}\n`);

        // ==================== FIX LINKS ====================
        console.log('📦 Links को ठीक किया जा रहा है...');
        const links = await linkCollection.find({}).toArray();
        let updatedLinks = 0;

        for (const link of links) {
            const totalVisits = parseInt(link.visits) || 0;
            const totalClaims = parseInt(link.claims) || 0;

            const newDailyVisits = {};
            const newDailyClaims = {};

            if (totalVisits > 0) {
                newDailyVisits[today] = totalVisits;
            }
            if (totalClaims > 0) {
                newDailyClaims[today] = totalClaims;
            }

            await linkCollection.updateOne(
                { _id: link._id },
                { 
                    $set: { 
                        dailyVisits: newDailyVisits,
                        dailyClaims: newDailyClaims
                    } 
                }
            );
            updatedLinks++;
            console.log(`  ✅ ${link.name || link.id}: visits=${totalVisits}, claims=${totalClaims}`);
        }
        console.log(`\n✅ ${updatedLinks} links updated\n`);

        // ==================== FIX STATS ====================
        console.log('📦 Stats को ठीक किया जा रहा है...');
        const statsDocs = await statsCollection.find({}).toArray();
        let updatedStats = 0;

        for (const stat of statsDocs) {
            const totalVisitors = parseInt(stat.totalVisitors) || 0;
            const totalClaims = parseInt(stat.totalClaims) || 0;

            const newDailyVisitors = {};
            const newDailyClaims = {};

            if (totalVisitors > 0) {
                newDailyVisitors[today] = totalVisitors;
            }
            if (totalClaims > 0) {
                newDailyClaims[today] = totalClaims;
            }

            await statsCollection.updateOne(
                { _id: stat._id },
                { 
                    $set: { 
                        dailyVisitors: newDailyVisitors,
                        dailyClaims: newDailyClaims
                    },
                    $unset: {
                        uniqueVisitors: "",
                        uniqueClaims: "",
                        activeSessions: "",
                        minuteClaims: "",
                        minuteVisitors: "",
                        hourlyClaims: "",
                        hourlyVisitors: ""
                    }
                }
            );
            updatedStats++;
        }
        console.log(`✅ ${statsUpdated || updatedStats} stats updated\n`);

        console.log('🎉 सब कुछ ठीक हो गया!');
        console.log(`\n📊 अब आपके डेटाबेस में:`);
        console.log(`   - सारा पुराना डेटा आज की तारीख (${today}) में डाल दिया गया है।`);
        console.log(`   - अब Admin Panel और User Dashboard में Today/Yesterday/7 Days सही दिखेगा।`);

        await mongoose.connection.close();
        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
}

fixData();