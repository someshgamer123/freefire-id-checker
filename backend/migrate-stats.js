require('dotenv').config();
const mongoose = require('mongoose');

const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/free_redeemcode';

async function migrate() {
    try {
        console.log('🔄 Connecting to MongoDB...');
        await mongoose.connect(MONGO_URI);
        console.log('✅ Connected');

        const db = mongoose.connection.db;
        const linkCollection = db.collection('links');
        const statsCollection = db.collection('stats');

        console.log('\n📦 Migrating Links...');
        const links = await linkCollection.find({}).toArray();
        let linksUpdated = 0;

        for (const link of links) {
            let needsUpdate = false;
            const updateFields = {};

            if (link.dailyVisits) {
                if (link.dailyVisits instanceof Map) {
                    updateFields.dailyVisits = Object.fromEntries(link.dailyVisits);
                    needsUpdate = true;
                } else if (typeof link.dailyVisits === 'object') {
                    const cleaned = {};
                    for (const key in link.dailyVisits) {
                        if (link.dailyVisits.hasOwnProperty(key)) {
                            cleaned[key] = parseInt(link.dailyVisits[key]) || 0;
                        }
                    }
                    if (JSON.stringify(cleaned) !== JSON.stringify(link.dailyVisits)) {
                        updateFields.dailyVisits = cleaned;
                        needsUpdate = true;
                    }
                }
            }

            if (link.dailyClaims) {
                if (link.dailyClaims instanceof Map) {
                    updateFields.dailyClaims = Object.fromEntries(link.dailyClaims);
                    needsUpdate = true;
                } else if (typeof link.dailyClaims === 'object') {
                    const cleaned = {};
                    for (const key in link.dailyClaims) {
                        if (link.dailyClaims.hasOwnProperty(key)) {
                            cleaned[key] = parseInt(link.dailyClaims[key]) || 0;
                        }
                    }
                    if (JSON.stringify(cleaned) !== JSON.stringify(link.dailyClaims)) {
                        updateFields.dailyClaims = cleaned;
                        needsUpdate = true;
                    }
                }
            }

            if (needsUpdate) {
                await linkCollection.updateOne({ _id: link._id }, { $set: updateFields });
                linksUpdated++;
            }
        }
        console.log(`✅ Links updated: ${linksUpdated}`);

        console.log('\n📦 Migrating Stats...');
        const statsDocs = await statsCollection.find({}).toArray();
        let statsUpdated = 0;

        for (const stat of statsDocs) {
            let needsUpdate = false;
            const updateFields = {};

            if (stat.dailyVisitors) {
                if (stat.dailyVisitors instanceof Map) {
                    updateFields.dailyVisitors = Object.fromEntries(stat.dailyVisitors);
                    needsUpdate = true;
                } else if (typeof stat.dailyVisitors === 'object') {
                    const cleaned = {};
                    for (const key in stat.dailyVisitors) {
                        if (stat.dailyVisitors.hasOwnProperty(key)) {
                            cleaned[key] = parseInt(stat.dailyVisitors[key]) || 0;
                        }
                    }
                    updateFields.dailyVisitors = cleaned;
                    needsUpdate = true;
                }
            }

            if (stat.dailyClaims) {
                if (stat.dailyClaims instanceof Map) {
                    updateFields.dailyClaims = Object.fromEntries(stat.dailyClaims);
                    needsUpdate = true;
                } else if (typeof stat.dailyClaims === 'object') {
                    const cleaned = {};
                    for (const key in stat.dailyClaims) {
                        if (stat.dailyClaims.hasOwnProperty(key)) {
                            cleaned[key] = parseInt(stat.dailyClaims[key]) || 0;
                        }
                    }
                    updateFields.dailyClaims = cleaned;
                    needsUpdate = true;
                }
            }

            if (needsUpdate) {
                await statsCollection.updateOne({ _id: stat._id }, { $set: updateFields });
                statsUpdated++;
            }
        }
        console.log(`✅ Stats updated: ${statsUpdated}`);

        console.log('\n🎉 Migration Complete!');
        await mongoose.connection.close();
        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
}

migrate();
