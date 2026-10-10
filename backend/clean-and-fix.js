// clean-and-fix.js
// पुराने गलत claim डेटा को ठीक करता है + daily data को IST आज की तारीख में डालता है
// Command: node clean-and-fix.js

require('dotenv').config();
const mongoose = require('mongoose');

const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/free_redeemcode';

async function cleanAndFix() {
    try {
        console.log('🔄 MongoDB से कनेक्ट हो रहा है...');
        await mongoose.connect(MONGO_URI);
        console.log('✅ Connected to MongoDB\n');

        const db = mongoose.connection.db;
        const linkCollection = db.collection('links');
        const statsCollection = db.collection('stats');

        const now = new Date();
        const istOffset = 5.5 * 60 * 60 * 1000;
        const istNow = new Date(now.getTime() + istOffset);
        const today = istNow.toISOString().split('T')[0];

        console.log(`📅 आज की तारीख (IST): ${today}\n`);

        // ==================== LINKS को ठीक करें ====================
        console.log('📦 Links को ठीक किया जा रहा है...\n');
        const links = await linkCollection.find({}).toArray();
        let fixedLinks = 0;

        for (const link of links) {
            let visits = parseInt(link.visits) || 0;
            let claims = parseInt(link.claims) || 0;

            // ✅ FIX: अगर claims > visits, तो claims को visits का 70% कर दें
            let correctedClaims = claims;
            if (claims > visits && visits > 0) {
                correctedClaims = Math.floor(visits * 0.7);
                console.log(`  ⚠️  ${link.name || link.id}: claims ${claims} → ${correctedClaims} (visits: ${visits})`);
            }

            const newDailyVisits = visits > 0 ? { [today]: visits } : {};
            const newDailyClaims = correctedClaims > 0 ? { [today]: correctedClaims } : {};

            await linkCollection.updateOne(
                { _id: link._id },
                {
                    $set: {
                        visits: visits,
                        claims: correctedClaims,
                        dailyVisits: newDailyVisits,
                        dailyClaims: newDailyClaims
                    }
                }
            );
            fixedLinks++;
            console.log(`  ✅ ${link.name || link.id}: visits=${visits}, claims=${correctedClaims}`);
        }
        console.log(`\n✅ ${fixedLinks} links fixed\n`);

        // ==================== STATS को ठीक करें ====================
        console.log('📦 Stats को ठीक किया जा रहा है...\n');
        const statsDocs = await statsCollection.find({}).toArray();
        let fixedStats = 0;

        for (const stat of statsDocs) {
            let totalVisitors = parseInt(stat.totalVisitors) || 0;
            let totalClaims = parseInt(stat.totalClaims) || 0;

            let correctedTotalClaims = totalClaims;
            if (totalClaims > totalVisitors && totalVisitors > 0) {
                correctedTotalClaims = Math.floor(totalVisitors * 0.7);
                console.log(`  ⚠️  Stats: totalClaims ${totalClaims} → ${correctedTotalClaims} (visits: ${totalVisitors})`);
            }

            const newDailyVisitors = totalVisitors > 0 ? { [today]: totalVisitors } : {};
            const newDailyClaims = correctedTotalClaims > 0 ? { [today]: correctedTotalClaims } : {};

            await statsCollection.updateOne(
                { _id: stat._id },
                {
                    $set: {
                        totalVisitors: totalVisitors,
                        totalClaims: correctedTotalClaims,
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
            fixedStats++;
        }
        console.log(`✅ ${fixedStats} stats fixed\n`);

        console.log('🎉 सब कुछ ठीक हो गया!');
        console.log(`📊 Summary:`);
        console.log(`   - Links fixed: ${fixedLinks}`);
        console.log(`   - Stats fixed: ${fixedStats}`);
        console.log(`   - सारा पुराना डेटा आज की तारीख (${today}) में डाल दिया गया।`);
        console.log(`\n👉 अब सर्वर restart करें: npm start`);

        await mongoose.connection.close();
        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
}

cleanAndFix();