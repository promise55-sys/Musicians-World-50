'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { backupKey, encryptFile } = require('./backup-crypto');

const DATA_DIR = process.env.AUTH_DATA_DIR || path.join(process.env.LOCALAPPDATA || process.env.HOME || os.tmpdir(), 'NorthstarAccess');
const DB_PATH = path.join(DATA_DIR, 'northstar.sqlite');
const DATABASE_MODE = process.env.DATABASE_MODE || (process.env.SUPABASE_DB_URL || process.env.DATABASE_URL ? 'supabase' : 'sqlite');
if (!['sqlite', 'postgres', 'supabase'].includes(DATABASE_MODE)) throw new Error('DATABASE_MODE must be sqlite, postgres, or supabase.');
const REMOTE = DATABASE_MODE === 'postgres' || DATABASE_MODE === 'supabase';
const REMOTE_DATABASE_URL = DATABASE_MODE === 'supabase' ? (process.env.SUPABASE_DB_URL || process.env.DATABASE_URL) : process.env.DATABASE_URL;

if (REMOTE && !REMOTE_DATABASE_URL) throw new Error(DATABASE_MODE === 'supabase' ? 'Set SUPABASE_DB_URL to your Supabase PostgreSQL connection string.' : 'Set DATABASE_URL when DATABASE_MODE=postgres.');
if (!REMOTE && (process.env.DATABASE_URL || process.env.SUPABASE_DB_URL)) throw new Error('Remove the remote database URL or set DATABASE_MODE=supabase.');
if (process.env.NODE_ENV === 'production' && !REMOTE && !process.env.AUTH_DATA_DIR) {
	throw new Error('Production SQLite needs persistent storage. On Render, attach a persistent disk (for example mounted at /var/data) and set AUTH_DATA_DIR=/var/data. For serverless hosting, configure Supabase with DATABASE_MODE=supabase and SUPABASE_DB_URL.');
}

let db;
if (REMOTE) {
	const { Pool } = require('pg');
	const pool = new Pool({ connectionString: REMOTE_DATABASE_URL, max: 2, connectionTimeoutMillis: 10000, idleTimeoutMillis: 10000 });
	pool.on('error', (error) => console.error('Remote PostgreSQL pool error:', error.message));
	const executePostgres = async (query, client = pool) => {
		const sourceSql = typeof query === 'string' ? query : query.sql;
		const args = typeof query === 'string' ? [] : query.args || [];
		const pragma = /^PRAGMA\s+table_info\(\s*([a-z_][a-z0-9_]*)\s*\)\s*;?$/i.exec(sourceSql);
		let sql = sourceSql;
		let values = args;
		if (pragma) {
			sql = 'SELECT column_name AS name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1';
			values = [pragma[1].toLowerCase()];
		} else {
			let placeholder = 0;
			sql = sql
				.replace(/([a-z_][a-z0-9_.]*)\s*=\s*\?\s+COLLATE NOCASE|\?/gi, (match, column) => {
					placeholder += 1;
					return column ? `LOWER(${column}) = LOWER($${placeholder})` : `$${placeholder}`;
				})
				.replace(/\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b/gi, 'SERIAL PRIMARY KEY')
				.replace(/\bBLOB\b/gi, 'BYTEA')
				.replace(/\s+COLLATE\s+NOCASE\b/gi, '')
				.replace(/\bCURRENT_TIMESTAMP\b/gi, 'CURRENT_TIMESTAMP::text');
		}
		const result = await client.query(sql, values);
		return { rows: result.rows, rowsAffected: result.rowCount || 0 };
	};
	db = {
		execute: executePostgres,
		async transaction() {
			const client = await pool.connect();
			let released = false;
			try {
				await client.query('BEGIN');
			} catch (error) {
				client.release();
				throw error;
			}
			const release = () => {
				if (released) return;
				released = true;
				client.release();
			};
			return {
				execute: (query) => executePostgres(query, client),
				async commit() {
					try { await client.query('COMMIT'); }
					finally { release(); }
				},
				async rollback() {
					if (released) return;
					try { await client.query('ROLLBACK'); }
					finally { release(); }
				},
			};
		},
	};
} else {
	var Database = require('better-sqlite3');
	fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
	const localDatabase = new Database(DB_PATH);
	const execute = async (query) => {
		if (typeof query === 'string') {
			const statement = localDatabase.prepare(query);
			if (statement.reader) return { rows: statement.all() };
			localDatabase.exec(query);
			return { rows: [] };
		}
		const statement = localDatabase.prepare(query.sql);
		if (statement.reader) return { rows: statement.all(query.args || []) };
		const result = statement.run(query.args || []);
		return { rows: [], rowsAffected: result.changes, lastInsertRowid: result.lastInsertRowid };
	};
	db = {
		execute,
		async transaction() {
			localDatabase.exec('BEGIN IMMEDIATE');
			return {
				execute,
				async commit() { localDatabase.exec('COMMIT'); },
				async rollback() { localDatabase.exec('ROLLBACK'); },
			};
		},
	};
}

let schemaReady;
let backupQueue = Promise.resolve();
let backupTimer;
let dailyBackupTimer;

function scheduleLocalBackup() {
	if (REMOTE) return;
	clearTimeout(backupTimer);
	backupTimer = setTimeout(() => {
		backupTimer = null;
		backupQueue = backupQueue.catch(() => {}).then(() => maintainLocalDailyBackup());
		backupQueue.catch((error) => console.error('Automatic database backup failed:', error.message));
	}, 500);
}

function startLocalBackupSchedule() {
	if (REMOTE || dailyBackupTimer) return;
	scheduleLocalBackup();
	dailyBackupTimer = setInterval(scheduleLocalBackup, 24 * 60 * 60 * 1000);
	dailyBackupTimer.unref();
}

function isWrite(sql) {
	return /^\s*(?:INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql);
}

async function initializeDatabase() {
	if (schemaReady) return schemaReady;
	schemaReady = (async () => {
		await db.execute(`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL COLLATE NOCASE UNIQUE,
			full_name TEXT NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('admin', 'staff', 'viewer')),
			password_salt TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
				totp_pending_secret TEXT,
			last_totp_step INTEGER NOT NULL DEFAULT -1,
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			locked_until INTEGER NOT NULL DEFAULT 0,
			auth_version INTEGER NOT NULL DEFAULT 0,
				signature_public_key TEXT,
				email TEXT COLLATE NOCASE UNIQUE,
				google_sub TEXT,
				country TEXT NOT NULL DEFAULT '',
				country_code TEXT NOT NULL DEFAULT '',
				approval_status TEXT NOT NULL DEFAULT 'approved',
				approval_due_at TEXT,
				approved_at TEXT,
				created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
			)`);
		await db.execute(`CREATE TABLE IF NOT EXISTS deleted_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			original_id INTEGER NOT NULL,
			username TEXT NOT NULL,
			full_name TEXT NOT NULL,
			role TEXT NOT NULL,
			email TEXT,
			country TEXT NOT NULL DEFAULT '',
			country_code TEXT NOT NULL DEFAULT '',
			approval_status TEXT,
			approval_due_at TEXT,
			created_at TEXT,
			approved_at TEXT,
			deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			deleted_by_id INTEGER NOT NULL,
			deleted_by_username TEXT NOT NULL
			)`);
		await db.execute(`CREATE TABLE IF NOT EXISTS password_recovery (
			user_id INTEGER PRIMARY KEY,
			code_hash TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			requested_at INTEGER NOT NULL,
			window_started_at INTEGER NOT NULL,
			send_count INTEGER NOT NULL DEFAULT 0
			)`);
		await db.execute(`CREATE TABLE IF NOT EXISTS musician_profiles (
			user_id INTEGER PRIMARY KEY,
			location TEXT NOT NULL DEFAULT '',
			country TEXT NOT NULL DEFAULT '',
			member_type TEXT NOT NULL DEFAULT 'viewer',
			avatar_preset TEXT NOT NULL DEFAULT 'guitar',
			instruments TEXT NOT NULL DEFAULT '',
			genres TEXT NOT NULL DEFAULT '',
			bio TEXT NOT NULL DEFAULT '',
			contact_email TEXT NOT NULL DEFAULT '',
			avatar_data BLOB,
			avatar_mime TEXT,
			share_location INTEGER NOT NULL DEFAULT 0,
			latitude REAL,
			longitude REAL,
			language TEXT NOT NULL DEFAULT 'en',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		const profileColumns = new Set((await db.execute('PRAGMA table_info(musician_profiles)')).rows.map((row) => String(row.name)));
		if (!profileColumns.has('country')) await db.execute("ALTER TABLE musician_profiles ADD COLUMN country TEXT NOT NULL DEFAULT ''");
		if (!profileColumns.has('member_type')) await db.execute("ALTER TABLE musician_profiles ADD COLUMN member_type TEXT NOT NULL DEFAULT 'viewer'");
		if (!profileColumns.has('avatar_preset')) await db.execute("ALTER TABLE musician_profiles ADD COLUMN avatar_preset TEXT NOT NULL DEFAULT 'guitar'");
		if (!profileColumns.has('avatar_data')) await db.execute('ALTER TABLE musician_profiles ADD COLUMN avatar_data BLOB');
		if (!profileColumns.has('avatar_mime')) await db.execute('ALTER TABLE musician_profiles ADD COLUMN avatar_mime TEXT');
		if (!profileColumns.has('share_location')) await db.execute('ALTER TABLE musician_profiles ADD COLUMN share_location INTEGER NOT NULL DEFAULT 0');
		if (!profileColumns.has('latitude')) await db.execute('ALTER TABLE musician_profiles ADD COLUMN latitude REAL');
		if (!profileColumns.has('longitude')) await db.execute('ALTER TABLE musician_profiles ADD COLUMN longitude REAL');
		if (!profileColumns.has('language')) await db.execute("ALTER TABLE musician_profiles ADD COLUMN language TEXT NOT NULL DEFAULT 'en'");
		await db.execute('CREATE TABLE IF NOT EXISTS app_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
		const viewerProfileMigration = 'classify-empty-musician-profiles-as-viewers-v1';
		const appliedViewerProfileMigration = await db.execute({ sql: 'SELECT name FROM app_migrations WHERE name = ?', args: [viewerProfileMigration] });
		if (!appliedViewerProfileMigration.rows.length) {
			await db.execute("UPDATE musician_profiles SET member_type = 'viewer' WHERE member_type = 'singer' AND location = '' AND country = '' AND instruments = '' AND genres = '' AND bio = '' AND contact_email = '' AND avatar_data IS NULL AND avatar_preset = 'guitar' AND share_location = 0 AND latitude IS NULL AND longitude IS NULL");
			await db.execute({ sql: 'INSERT INTO app_migrations (name) VALUES (?) ON CONFLICT(name) DO NOTHING', args: [viewerProfileMigration] });
		}
		await db.execute(`CREATE TABLE IF NOT EXISTS music_posts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			author_id INTEGER NOT NULL,
			kind TEXT NOT NULL CHECK (kind IN ('idea', 'collab')),
			body TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute(`CREATE TABLE IF NOT EXISTS music_post_replies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			post_id INTEGER NOT NULL,
			author_id INTEGER NOT NULL,
			body TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute('CREATE INDEX IF NOT EXISTS idx_music_post_replies_post ON music_post_replies (post_id, created_at, id)');
		await db.execute(`CREATE TABLE IF NOT EXISTS gig_listings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			poster_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			location TEXT NOT NULL,
			event_date TEXT NOT NULL,
			description TEXT NOT NULL,
			contact_email TEXT NOT NULL DEFAULT '',
			opportunity_type TEXT NOT NULL DEFAULT 'gig',
			compensation TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute(`CREATE TABLE IF NOT EXISTS music_tracks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			author_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			genre TEXT NOT NULL DEFAULT '',
			note TEXT NOT NULL DEFAULT '',
			audio_url TEXT NOT NULL,
			media_type TEXT NOT NULL DEFAULT 'audio',
			audio_data BLOB,
			audio_mime TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		const gigColumns = new Set((await db.execute('PRAGMA table_info(gig_listings)')).rows.map((row) => String(row.name)));
		if (!gigColumns.has('opportunity_type')) await db.execute("ALTER TABLE gig_listings ADD COLUMN opportunity_type TEXT NOT NULL DEFAULT 'gig'");
		if (!gigColumns.has('compensation')) await db.execute("ALTER TABLE gig_listings ADD COLUMN compensation TEXT NOT NULL DEFAULT ''");
		const trackColumns = new Set((await db.execute('PRAGMA table_info(music_tracks)')).rows.map((row) => String(row.name)));
		if (!trackColumns.has('media_type')) await db.execute("ALTER TABLE music_tracks ADD COLUMN media_type TEXT NOT NULL DEFAULT 'audio'");
		if (!trackColumns.has('audio_data')) await db.execute('ALTER TABLE music_tracks ADD COLUMN audio_data BLOB');
		if (!trackColumns.has('audio_mime')) await db.execute('ALTER TABLE music_tracks ADD COLUMN audio_mime TEXT');
		await db.execute(`CREATE TABLE IF NOT EXISTS music_track_likes (
			track_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (track_id, user_id)
		)`);
		await db.execute(`CREATE TABLE IF NOT EXISTS music_track_comments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			track_id INTEGER NOT NULL,
			author_id INTEGER NOT NULL,
			body TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute(`CREATE TABLE IF NOT EXISTS account_activity (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			username TEXT NOT NULL,
			event TEXT NOT NULL CHECK (event IN ('sign_in', 'sign_out')),
			occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute('CREATE INDEX IF NOT EXISTS idx_account_activity_user ON account_activity (user_id, occurred_at DESC)');
		await db.execute(`CREATE TABLE IF NOT EXISTS community_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			room TEXT NOT NULL CHECK (room IN ('singers', 'instrumentalists', 'marketplace', 'support')),
			author_id INTEGER NOT NULL,
			body TEXT NOT NULL,
			audio_data BLOB,
			audio_mime TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute('CREATE INDEX IF NOT EXISTS idx_community_messages_room ON community_messages (room, created_at DESC, id DESC)');
		const messageColumns = new Set((await db.execute('PRAGMA table_info(community_messages)')).rows.map((row) => String(row.name)));
		if (!messageColumns.has('audio_data')) await db.execute('ALTER TABLE community_messages ADD COLUMN audio_data BLOB');
		if (!messageColumns.has('audio_mime')) await db.execute('ALTER TABLE community_messages ADD COLUMN audio_mime TEXT');
		await db.execute(`CREATE TABLE IF NOT EXISTS community_chat_members (
			user_id INTEGER PRIMARY KEY,
			joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute(`CREATE TABLE IF NOT EXISTS community_general_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			author_id INTEGER NOT NULL,
			body TEXT NOT NULL,
			audio_data BLOB,
			audio_mime TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute('CREATE INDEX IF NOT EXISTS idx_community_general_messages_created ON community_general_messages (created_at DESC, id DESC)');
		await db.execute(`CREATE TABLE IF NOT EXISTS direct_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			sender_id INTEGER NOT NULL,
			recipient_id INTEGER NOT NULL,
			body TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute('CREATE INDEX IF NOT EXISTS idx_direct_messages_participants ON direct_messages (sender_id, recipient_id, created_at DESC, id DESC)');
		await db.execute('CREATE INDEX IF NOT EXISTS idx_direct_messages_recipient ON direct_messages (recipient_id, sender_id, created_at DESC, id DESC)');
		await db.execute(`CREATE TABLE IF NOT EXISTS marketplace_listings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			seller_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			category TEXT NOT NULL,
			price TEXT NOT NULL DEFAULT '',
			price_amount REAL,
			currency TEXT,
			stock INTEGER NOT NULL DEFAULT 1,
			location TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL,
			contact_email TEXT NOT NULL DEFAULT '',
			image_data BLOB,
			image_mime TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		const marketplaceColumns = new Set((await db.execute('PRAGMA table_info(marketplace_listings)')).rows.map((row) => String(row.name)));
		if (!marketplaceColumns.has('image_data')) await db.execute('ALTER TABLE marketplace_listings ADD COLUMN image_data BLOB');
		if (!marketplaceColumns.has('image_mime')) await db.execute('ALTER TABLE marketplace_listings ADD COLUMN image_mime TEXT');
		if (!marketplaceColumns.has('price_amount')) await db.execute('ALTER TABLE marketplace_listings ADD COLUMN price_amount REAL');
		if (!marketplaceColumns.has('currency')) await db.execute('ALTER TABLE marketplace_listings ADD COLUMN currency TEXT');
		if (!marketplaceColumns.has('stock')) await db.execute('ALTER TABLE marketplace_listings ADD COLUMN stock INTEGER NOT NULL DEFAULT 1');
		await db.execute(`CREATE TABLE IF NOT EXISTS marketplace_orders (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			listing_id INTEGER NOT NULL,
			seller_id INTEGER NOT NULL,
			buyer_id INTEGER NOT NULL,
			quantity INTEGER NOT NULL,
			amount_minor INTEGER NOT NULL,
			currency TEXT NOT NULL,
			reference TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL CHECK (status IN ('pending', 'paid', 'packing', 'shipped', 'delivered', 'cancelled')),
			inventory_issue INTEGER NOT NULL DEFAULT 0,
			buyer_name TEXT NOT NULL,
			buyer_email TEXT NOT NULL,
			buyer_phone TEXT NOT NULL,
			delivery_address TEXT NOT NULL,
			delivery_note TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		const orderColumns = new Set((await db.execute('PRAGMA table_info(marketplace_orders)')).rows.map((row) => String(row.name)));
		if (!orderColumns.has('inventory_issue')) await db.execute('ALTER TABLE marketplace_orders ADD COLUMN inventory_issue INTEGER NOT NULL DEFAULT 0');
		await db.execute('CREATE INDEX IF NOT EXISTS idx_marketplace_orders_seller ON marketplace_orders (seller_id, created_at DESC)');
		await db.execute('CREATE INDEX IF NOT EXISTS idx_marketplace_orders_buyer ON marketplace_orders (buyer_id, created_at DESC)');
		await db.execute(`CREATE TABLE IF NOT EXISTS community_calls (
			id TEXT PRIMARY KEY,
			room TEXT NOT NULL CHECK (room IN ('singers', 'instrumentalists', 'marketplace', 'support')),
			caller_id INTEGER NOT NULL,
			recipient_id INTEGER NOT NULL,
			media_type TEXT NOT NULL CHECK (media_type IN ('audio', 'video')),
			status TEXT NOT NULL CHECK (status IN ('ringing', 'active', 'declined', 'ended', 'expired')),
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute('CREATE INDEX IF NOT EXISTS idx_community_calls_recipient ON community_calls (recipient_id, status, created_at DESC)');
		await db.execute(`CREATE TABLE IF NOT EXISTS community_call_signals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			call_id TEXT NOT NULL,
			sender_id INTEGER NOT NULL,
			signal_type TEXT NOT NULL CHECK (signal_type IN ('offer', 'answer', 'ice')),
			payload TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`);
		await db.execute('CREATE INDEX IF NOT EXISTS idx_community_call_signals_call ON community_call_signals (call_id, id)');
		const result = await db.execute('PRAGMA table_info(users)');
		const names = new Set(result.rows.map((row) => String(row.name)));
		if (!names.has('totp_pending_secret')) await db.execute('ALTER TABLE users ADD COLUMN totp_pending_secret TEXT');
		if (!names.has('auth_version')) await db.execute('ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0');
		if (!names.has('signature_public_key')) await db.execute('ALTER TABLE users ADD COLUMN signature_public_key TEXT');
		if (!names.has('email')) {
			await db.execute('ALTER TABLE users ADD COLUMN email TEXT COLLATE NOCASE');
			await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email COLLATE NOCASE) WHERE email IS NOT NULL');
		}
		if (!names.has('approval_status')) await db.execute("ALTER TABLE users ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'approved'");
		if (!names.has('approved_at')) await db.execute('ALTER TABLE users ADD COLUMN approved_at TEXT');
		if (!names.has('google_sub')) await db.execute('ALTER TABLE users ADD COLUMN google_sub TEXT');
		if (!names.has('country')) await db.execute("ALTER TABLE users ADD COLUMN country TEXT NOT NULL DEFAULT ''");
		if (!names.has('country_code')) await db.execute("ALTER TABLE users ADD COLUMN country_code TEXT NOT NULL DEFAULT ''");
		if (!names.has('approval_due_at')) await db.execute('ALTER TABLE users ADD COLUMN approval_due_at TEXT');
		await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub_unique ON users(google_sub) WHERE google_sub IS NOT NULL');
		if (REMOTE) {
			await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_username_case_insensitive_unique ON users (LOWER(username))');
			await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_email_case_insensitive_unique ON users (LOWER(email)) WHERE email IS NOT NULL');
		}

		const deletedColumns = new Set((await db.execute('PRAGMA table_info(deleted_users)')).rows.map((row) => String(row.name)));
		if (!deletedColumns.has('country')) await db.execute("ALTER TABLE deleted_users ADD COLUMN country TEXT NOT NULL DEFAULT ''");
		if (!deletedColumns.has('country_code')) await db.execute("ALTER TABLE deleted_users ADD COLUMN country_code TEXT NOT NULL DEFAULT ''");
		if (!deletedColumns.has('approval_due_at')) await db.execute('ALTER TABLE deleted_users ADD COLUMN approval_due_at TEXT');
		if (!deletedColumns.has('password_salt')) await db.execute('ALTER TABLE deleted_users ADD COLUMN password_salt TEXT');
		if (!deletedColumns.has('password_hash')) await db.execute('ALTER TABLE deleted_users ADD COLUMN password_hash TEXT');
		if (!deletedColumns.has('totp_secret')) await db.execute('ALTER TABLE deleted_users ADD COLUMN totp_secret TEXT');
		if (!deletedColumns.has('last_totp_step')) await db.execute('ALTER TABLE deleted_users ADD COLUMN last_totp_step INTEGER NOT NULL DEFAULT -1');
		if (!deletedColumns.has('failed_attempts')) await db.execute('ALTER TABLE deleted_users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0');
		if (!deletedColumns.has('locked_until')) await db.execute('ALTER TABLE deleted_users ADD COLUMN locked_until INTEGER NOT NULL DEFAULT 0');
		if (!deletedColumns.has('auth_version')) await db.execute('ALTER TABLE deleted_users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0');
		if (!deletedColumns.has('signature_public_key')) await db.execute('ALTER TABLE deleted_users ADD COLUMN signature_public_key TEXT');
		if (!deletedColumns.has('google_sub')) await db.execute('ALTER TABLE deleted_users ADD COLUMN google_sub TEXT');
	})().catch((error) => { schemaReady = null; throw error; });
	return schemaReady;
}

async function one(sql, args = []) {
	const result = await db.execute({ sql, args });
	if (isWrite(sql)) scheduleLocalBackup();
	return result.rows[0] || null;
}

async function all(sql, args = []) {
	const result = await db.execute({ sql, args });
	return result.rows;
}

async function run(sql, args = []) {
	const result = await db.execute({ sql, args });
	if (isWrite(sql)) scheduleLocalBackup();
	return result;
}

async function transaction(callback) {
	const tx = await db.transaction('write');
	try {
		const value = await callback({
			one: async (sql, args = []) => (await tx.execute({ sql, args })).rows[0] || null,
			all: async (sql, args = []) => (await tx.execute({ sql, args })).rows,
			run: async (sql, args = []) => tx.execute({ sql, args }),
		});
		await tx.commit();
		scheduleLocalBackup();
		return value;
	} catch (error) {
		await tx.rollback();
		throw error;
	}
}

function replaceFile(tempPath, destination) {
	const previous = `${destination}.previous`;
	let movedPrevious = false;
	try {
		fs.rmSync(previous, { force: true });
		if (fs.existsSync(destination)) {
			fs.renameSync(destination, previous);
			movedPrevious = true;
		}
		fs.renameSync(tempPath, destination);
		fs.rmSync(previous, { force: true });
		try { fs.chmodSync(destination, 0o600); } catch {}
	} catch (error) {
		if (movedPrevious && !fs.existsSync(destination)) {
			try { fs.renameSync(previous, destination); } catch {}
		}
		throw error;
	}
}

async function encryptLegacyBackups(directory, key) {
	for (const name of fs.readdirSync(directory)) {
		const databaseMatch = /^northstar-(\d{4}-\d{2}-\d{2})\.sqlite$/.exec(name);
		const pepperMatch = /^pepper-(\d{4}-\d{2}-\d{2})\.key$/.exec(name);
		const match = databaseMatch || pepperMatch;
		if (!match) continue;
		const date = match[1];
		const isDatabase = Boolean(databaseMatch);
		const source = path.join(directory, name);
		const destination = path.join(directory, isDatabase ? `northstar-${date}.sqlite.enc` : `pepper-${date}.key.enc`);
		const temporary = `${destination}.${process.pid}.${Date.now()}.tmp`;
		if (!fs.existsSync(destination)) {
			await encryptFile(source, temporary, key, `${isDatabase ? 'database' : 'pepper'}:${date}`);
			replaceFile(temporary, destination);
		}
		fs.rmSync(source, { force: true });
	}
}

async function maintainLocalDailyBackup() {
	if (REMOTE) return;
	const backupDirectory = path.join(DATA_DIR, 'backups');
	fs.mkdirSync(backupDirectory, { recursive: true, mode: 0o700 });
	const date = new Date().toISOString().slice(0, 10);
	const key = backupKey(DATA_DIR);
	await encryptLegacyBackups(backupDirectory, key);
	const destination = path.join(backupDirectory, `northstar-${date}.sqlite.enc`);
	const pepperPath = path.join(DATA_DIR, 'pepper.key');
	const pepperDestination = path.join(backupDirectory, `pepper-${date}.key.enc`);
	const suffix = `${process.pid}.${Date.now()}`;
	const temporary = path.join(backupDirectory, `northstar-${date}.${suffix}.sqlite`);
	const encryptedTemporary = `${destination}.${suffix}.tmp`;
	const encryptedPepperTemporary = `${pepperDestination}.${suffix}.tmp`;
	let source;
	try {
		source = new Database(DB_PATH, { readonly: true, fileMustExist: true });
		await source.backup(temporary);
		source.close();
		source = null;
		await encryptFile(temporary, encryptedTemporary, key, `database:${date}`);
		if (fs.existsSync(pepperPath)) {
			await encryptFile(pepperPath, encryptedPepperTemporary, key, `pepper:${date}`);
		}
		replaceFile(encryptedTemporary, destination);
		if (fs.existsSync(encryptedPepperTemporary)) replaceFile(encryptedPepperTemporary, pepperDestination);
	} catch (error) {
		try { source?.close(); } catch {}
		try { fs.rmSync(temporary, { force: true }); } catch {}
		try { fs.rmSync(encryptedTemporary, { force: true }); } catch {}
		try { fs.rmSync(encryptedPepperTemporary, { force: true }); } catch {}
		throw error;
	}
	fs.rmSync(temporary, { force: true });
	for (const name of fs.readdirSync(backupDirectory)) {
		const match = /^northstar-(\d{4}-\d{2}-\d{2})\.sqlite\.enc$/.exec(name);
		if (match && Date.now() - Date.parse(`${match[1]}T00:00:00Z`) > 7 * 86400000) {
			fs.rmSync(path.join(backupDirectory, name), { force: true });
			fs.rmSync(path.join(backupDirectory, `pepper-${match[1]}.key.enc`), { force: true });
		}
	}
}

function listBackups() {
	if (REMOTE) return [];
	const backupDirectory = path.join(DATA_DIR, 'backups');
	if (!fs.existsSync(backupDirectory)) return [];
	return fs.readdirSync(backupDirectory)
		.filter((name) => /^northstar-\d{4}-\d{2}-\d{2}\.sqlite\.enc$/.test(name))
		.map((name) => {
			const date = name.slice('northstar-'.length, 'northstar-'.length + 10);
			const stat = fs.statSync(path.join(backupDirectory, name));
			return { filename: name, date, sizeBytes: stat.size, createdAt: stat.mtime.toISOString() };
		})
		.sort((a, b) => b.date.localeCompare(a.date));
}

module.exports = { db, DATA_DIR, DB_PATH, REMOTE, all, initializeDatabase, listBackups, maintainLocalDailyBackup, one, run, scheduleLocalBackup, startLocalBackupSchedule, transaction };
