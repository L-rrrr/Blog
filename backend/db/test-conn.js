require('dotenv').config();
const { Client } = require('pg');

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
	console.error('ERROR: DATABASE_URL not set in environment.');
	process.exit(1);
}

const c = new Client({ connectionString });

(async () => {
	try {
		await c.connect();
		console.log('connected');
		const res = await c.query('SELECT NOW()');
		console.log(res.rows);
	} catch (err) {
		console.error('Connection error:', err.message);
		console.error(err);
	} finally {
		await c.end();
	}
})();