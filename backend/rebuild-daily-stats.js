require('dotenv').config();
const mongoose = require('mongoose');

const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/free_redeemcode';

async function rebuild() {
    try {
        console.log('🔄 Connecting to MongoDB...');
        await mongoose.connect(MONGO_URI);
        console.log('✅ Connected');

        const db = mongoose.connection.db;
        const linkCollection = db.collection('links');
        const statsCollection = db.collection('stats');

        const now = new Date();
        const istOffset = 5.5 * 60 * 60 * 1000;
        const istNow = new Date(now.getTime() + istOffset);
        const today = istNow.toISOString().split('T')[0];

        console.log(`📅 Today (IST): ${today}`);

        console.log('\n📦 Rebuilding Links...');
        const links = await linkCollection.find({}).toArray();
        let updated = 0;

        for (const link of links) {
            const totalVisits = parseInt(link.visits) || 0;
            const totalClaims = parseInt(link.claims) || 0;

            let dailyVisits = link.dailyVisits || {};
            let dailyClaims = link.dailyClaims || {};

            if (dailyVisits instanceof Map) dailyVisits = Object.fromEntries(dailyVisits);
            if (dailyClaims instanceof Map) dailyClaims = Object.fromEntries(dailyClaims);

            let calculatedVisits = 0;
            for (const key in dailyVisits) {
                calculatedVisits += parseInt(dailyVisits[key]) || 0;
            }

            let calculatedClaims = 0;
            for (const key in dailyClaims) {
                calculatedClaims += parseInt(dailyClaims[key]) || 0;
            }

            if (calculatedVisits === 0 && totalVisits > 0) {
                dailyVisits[today] = totalVisits;
                calculatedVisits = totalVisits;
                console.log(`  ⚠️ ${link.name || link.id}: ${totalVisits} visits → today`);
            }

            if (calculatedClaims === 0 && totalClaims > 0) {
                dailyClaims[today] = totalClaims;
                calculatedClaims = totalClaims;
                console.log(`  ⚠️ ${link.name || link.id}: ${totalClaims} claims → today`);
            }

            await linkCollection.updateOne(
                { _id: link._id },
                { 
                    $set: { 
                        dailyVisits: dailyVisits, 
                        dailyClaims: dailyClaims,
                        visits: calculatedVisits,
                        claims: calculatedClaims
                    } 
                }
            );
            updated++;
        }
        console.log(`✅ Links updated: ${updated}`);

        console.log('\n📦 Rebuilding Stats...');
        const statsDocs = await statsCollection.find({}).toArray();
        let statsUpdated = 0;

        for (const stat of statsDocs) {
            let dailyVisitors = stat.dailyVisitors || {};
            let dailyClaims = stat.dailyClaims || {};

            if (dailyVisitors instanceof Map) dailyVisitors = Object.fromEntries(dailyVisitors);
            if (dailyClaims instanceof Map) dailyClaims = Object.fromEntries(dailyClaims);

            let calcV = 0;
            for (const k in dailyVisitors) calcV += parseInt(dailyVisitors[k]) || 0;
            let calcC = 0;
            for (const k in dailyClaims) calcC += parseInt(dailyClaims[k]) || 0;

            if (calcV === 0 && (stat.totalVisitors || 0) > 0) {
                dailyVisitors[today] = stat.totalVisitors;
            }
            if (calcC === 0 && (stat.totalClaims || 0) > 0) {
                dailyClaims[today] = stat.totalClaims;
            }

            await statsCollection.updateOne(
                { _id: stat._id },
                { $set: { dailyVisitors: dailyVisitors, dailyClaims: dailyClaims } }
            );
            statsUpdated++;
        }
        console.log(`✅ Stats updated: ${statsUpdated}`);

        console.log('\n🎉 Rebuild Complete!');
        await mongoose.connection.close();
        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
}

rebuild();