// migrate-stats.js
// Run this script ONCE to convert old Map format data to new Object format
// Command: node migrate-stats.js

require('dotenv').config();
const mongoose = require('mongoose');

const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/free_redeemcode';

async function migrate() {
    try {
        console.log('🔄 Connecting to MongoDB...');
        await mongoose.connect(MONGO_URI);
        console.log('✅ Connected to MongoDB');

        const db = mongoose.connection.db;
        const linkCollection = db.collection('links');
        const statsCollection = db.collection('stats');

        // ==================== MIGRATE LINKS ====================
        console.log('\n📦 Migrating Links...');
        const links = await linkCollection.find({}).toArray();
        let linksUpdated = 0;

        for (const link of links) {
            let needsUpdate = false;
            const updateFields = {};

            // Convert dailyVisits from Map to Object
            if (link.dailyVisits) {
                if (link.dailyVisits instanceof Map) {
                    updateFields.dailyVisits = Object.fromEntries(link.dailyVisits);
                    needsUpdate = true;
                } else if (typeof link.dailyVisits === 'object' && !Array.isArray(link.dailyVisits)) {
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

            // Convert dailyClaims from Map to Object
            if (link.dailyClaims) {
                if (link.dailyClaims instanceof Map) {
                    updateFields.dailyClaims = Object.fromEntries(link.dailyClaims);
                    needsUpdate = true;
                } else if (typeof link.dailyClaims === 'object' && !Array.isArray(link.dailyClaims)) {
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
                console.log(`  ✅ Updated Link: ${link.name || link.id || link._id}`);
            }
        }
        console.log(`\n✅ Links Migration Complete: ${linksUpdated} links updated`);

        // ==================== MIGRATE STATS ====================
        console.log('\n📦 Migrating Global Stats...');
        const statsDocs = await statsCollection.find({}).toArray();
        let statsUpdated = 0;

        for (const stat of statsDocs) {
            let needsUpdate = false;
            const updateFields = {};

            if (stat.dailyVisitors) {
                if (stat.dailyVisitors instanceof Map) {
                    updateFields.dailyVisitors = Object.fromEntries(stat.dailyVisitors);
                    needsUpdate = true;
                } else if (typeof stat.dailyVisitors === 'object' && !Array.isArray(stat.dailyVisitors)) {
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
                } else if (typeof stat.dailyClaims === 'object' && !Array.isArray(stat.dailyClaims)) {
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
                console.log(`  ✅ Updated Stats document`);
            }
        }
        console.log(`\n✅ Stats Migration Complete: ${statsUpdated} stats documents updated`);

        // ==================== RE-CALCULATE TOTAL VISITS & CLAIMS ====================
        console.log('\n🔄 Re-calculating Total Visits & Claims from daily data...');
        
        const allLinks = await linkCollection.find({}).toArray();
        let recalculated = 0;

        for (const link of allLinks) {
            let totalVisits = 0;
            let totalClaims = 0;

            if (link.dailyVisits) {
                if (link.dailyVisits instanceof Map) {
                    for (const count of link.dailyVisits.values()) {
                        totalVisits += parseInt(count) || 0;
                    }
                } else {
                    for (const key in link.dailyVisits) {
                        if (link.dailyVisits.hasOwnProperty(key)) {
                            totalVisits += parseInt(link.dailyVisits[key]) || 0;
                        }
                    }
                }
            }

            if (link.dailyClaims) {
                if (link.dailyClaims instanceof Map) {
                    for (const count of link.dailyClaims.values()) {
                        totalClaims += parseInt(count) || 0;
                    }
                } else {
                    for (const key in link.dailyClaims) {
                        if (link.dailyClaims.hasOwnProperty(key)) {
                            totalClaims += parseInt(link.dailyClaims[key]) || 0;
                        }
                    }
                }
            }

            if (totalVisits !== (link.visits || 0) || totalClaims !== (link.claims || 0)) {
                await linkCollection.updateOne(
                    { _id: link._id },
                    { $set: { visits: totalVisits, claims: totalClaims } }
                );
                recalculated++;
                console.log(`  ✅ Recalculated Link: ${link.name || link.id} | Visits: ${totalVisits}, Claims: ${totalClaims}`);
            }
        }
        console.log(`\n✅ Recalculation Complete: ${recalculated} links updated`);

        console.log('\n🎉 Migration completed successfully!');
        console.log('📊 Summary:');
        console.log(`   - Links updated: ${linksUpdated}`);
        console.log(`   - Stats updated: ${statsUpdated}`);
        console.log(`   - Links recalculated: ${recalculated}`);
        
        await mongoose.connection.close();
        process.exit(0);
    } catch (error) {
        console.error('❌ Migration error:', error);
        process.exit(1);
    }
}

migrate();