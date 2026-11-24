'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');
const store = require('./database');
const mail = require('./email');
const { backupKey, decryptFile } = require('./backup-crypto');
const { countryCode: countryCodeForName, countryName, countryOptions } = require('./countries');

const SESSION_NAME = 'northstar_session';
const MAX_BODY = 64 * 1024;
const MAX_PROFILE_BODY = 4.25 * 1024 * 1024;
const MAX_TRACK_BODY = 4.25 * 1024 * 1024;
const MAX_MARKET_BODY = 2.9 * 1024 * 1024;
const MAX_CHAT_AUDIO_BODY = 2.1 * 1024 * 1024;
const MAX_TRACK_AUDIO = 3 * 1024 * 1024;
const MAX_CHAT_AUDIO = 1.5 * 1024 * 1024;
const MAX_AVATAR_IMAGE = 5 * 1024 * 1024;
const MAX_MARKET_IMAGE = 2 * 1024 * 1024;
const MEMBER_TYPES = new Set(['singer', 'instrumentalist', 'seller']);
const AVATAR_PRESETS = new Set(['guitar', 'microphone', 'drums', 'keyboard', 'notes']);
const LANGUAGES = new Set(['en', 'es', 'fr', 'pt', 'sw']);
const CHAT_ROOMS = new Set(['singers', 'instrumentalists', 'marketplace', 'support']);
const SUPPORTED_SHOP_CURRENCIES = new Map([['GH', 'GHS'], ['US', 'USD']]);
let pepperValue;
let backupAttempted = false;
let googleClient;

function currencyForCountry(countryCode) {
	return SUPPORTED_SHOP_CURRENCIES.get(String(countryCode || '').toUpperCase()) || '';
}

function moneyMinorUnits(amount) {
	return Math.round(Number(amount) * 100);
}

function createIceServers(userId) {
	const iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
	const urls = String(process.env.TURN_URLS || '').split(',').map((url) => url.trim()).filter(Boolean);
	const sharedSecret = process.env.TURN_SHARED_SECRET || '';
	if (!urls.length && !sharedSecret) return { iceServers, turnConfigured: false };
	if (!urls.length || Buffer.byteLength(sharedSecret) < 32 || urls.some((url) => !/^turns?:/i.test(url))) {
		throw new HttpError(503, 'TURN is not configured correctly. Set TURN_URLS and a private TURN_SHARED_SECRET of at least 32 characters.');
	}
	const expires = Math.floor(Date.now() / 1000) + 3600;
	const username = `${expires}:${userId}`;
	const credential = crypto.createHmac('sha1', sharedSecret).update(username).digest('base64');
	iceServers.push({ urls, username, credential });
	return { iceServers, turnConfigured: true };
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function encodeBase32(buffer) {
	let bits = 0;
	let value = 0;
	let output = '';
	for (const byte of buffer) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) { output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
	}
	if (bits) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
	return output;
}

function decodeBase32(secret) {
	let bits = 0;
	let value = 0;
	const output = [];
	for (const character of String(secret).toUpperCase().replace(/=+$/g, '')) {
		const digit = BASE32_ALPHABET.indexOf(character);
		if (digit < 0) throw new Error('Invalid authenticator secret.');
		value = (value << 5) | digit;
		bits += 5;
		if (bits >= 8) { output.push((value >>> (bits - 8)) & 255); bits -= 8; }
	}
	return Buffer.from(output);
}

function encryptTotpSecret(secret) {
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey(), iv);
	cipher.setAAD(Buffer.from('northstar/totp/v1'));
	const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
	return `v1:${iv.toString('base64url')}:${cipher.getAuthTag().toString('base64url')}:${ciphertext.toString('base64url')}`;
}

function decryptTotpSecret(value) {
	const stored = String(value || '');
	if (!stored.startsWith('v1:')) return stored;
	const [, ivText, tagText, ciphertextText] = stored.split(':');
	try {
		const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey(), Buffer.from(ivText, 'base64url'));
		decipher.setAAD(Buffer.from('northstar/totp/v1'));
		decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
		return Buffer.concat([decipher.update(Buffer.from(ciphertextText, 'base64url')), decipher.final()]).toString('utf8');
	} catch { throw new Error('The stored authenticator secret could not be decrypted. Check that AUTH_PEPPER has not changed.'); }
}

function totpAt(secret, step) {
	const counter = Buffer.alloc(8);
	counter.writeBigUInt64BE(BigInt(step));
	const digest = crypto.createHmac('sha1', decodeBase32(secret)).update(counter).digest();
	const offset = digest[digest.length - 1] & 15;
	const code = (digest.readUInt32BE(offset) & 0x7fffffff) % 1000000;
	return String(code).padStart(6, '0');
}

function matchingTotpStep(secret, code, now = Date.now()) {
	if (!/^\d{6}$/.test(String(code || ''))) return null;
	const current = Math.floor(now / 30000);
	for (const step of [current - 1, current, current + 1]) {
		if (crypto.timingSafeEqual(Buffer.from(totpAt(secret, step)), Buffer.from(String(code)))) return step;
	}
	return null;
}

if (store.REMOTE && !process.env.AUTH_PEPPER) throw new Error('Set AUTH_PEPPER before starting with a remote database.');
if (process.env.AUTH_PEPPER && Buffer.byteLength(process.env.AUTH_PEPPER) < 32) throw new Error('AUTH_PEPPER must contain at least 32 characters.');

function pepper() {
	if (pepperValue) return pepperValue;
	const configured = process.env.AUTH_PEPPER;
	if (configured) {
		if (Buffer.byteLength(configured) < 32) throw new Error('AUTH_PEPPER must contain at least 32 characters.');
		pepperValue = `*${configured}*`;
		return pepperValue;
	}
	if (store.REMOTE) throw new Error('AUTH_PEPPER must be configured when using a remote database.');
	const file = path.join(store.DATA_DIR, 'pepper.key');
	try { fs.writeFileSync(file, `*${crypto.randomBytes(32).toString('hex')}*`, { flag: 'wx', mode: 0o600 }); }
	catch (error) { if (error.code !== 'EEXIST') throw error; }
	pepperValue = fs.readFileSync(file, 'utf8');
	if (Buffer.byteLength(pepperValue) < 32) throw new Error('Cannot read or create the private pepper key.');
	return pepperValue;
}

function sessionKey() {
	return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(pepper(), 'utf8'), Buffer.alloc(0), Buffer.from('northstar/session/v1', 'utf8'), 32));
}

function encodeSession(session) {
	const payload = Buffer.from(JSON.stringify(session)).toString('base64url');
	const signature = crypto.createHmac('sha256', sessionKey()).update(payload).digest('base64url');
	return `${payload}.${signature}`;
}

function readSession(req) {
	try {
		const cookies = String(req.headers.cookie || '').split(';');
		const cookie = cookies.map((part) => part.trim()).find((part) => part.startsWith(`${SESSION_NAME}=`));
		if (!cookie) return null;
		const value = decodeURIComponent(cookie.slice(SESSION_NAME.length + 1));
		const [payload, signature] = value.split('.');
		if (!payload || !signature) return null;
		const expected = crypto.createHmac('sha256', sessionKey()).update(payload).digest();
		const actual = Buffer.from(signature, 'base64url');
		if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
		const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
		return session && Number.isSafeInteger(session.expiresAt) && session.expiresAt > Date.now() ? session : null;
	} catch { return null; }
}

function cookie(req, session) {
	const secure = process.env.NODE_ENV === 'production' || Boolean(req.socket?.encrypted);
	return `${SESSION_NAME}=${encodeURIComponent(encodeSession(session))}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800${secure ? '; Secure' : ''}`;
}

function newSession() {
	return { csrfToken: crypto.randomBytes(32).toString('hex'), expiresAt: Date.now() + 30 * 60 * 1000 };
}

function json(res, status, data, headers = {}) {
	const body = JSON.stringify(data);
	res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', ...headers });
	res.end(body);
}

function parseBody(req, maxBody = MAX_BODY) {
	if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return Promise.resolve(req.body);
	if (typeof req.body === 'string') {
		try { return Promise.resolve(JSON.parse(req.body)); } catch { return Promise.reject(new HttpError(400, 'Request body must be valid JSON.')); }
	}
	return new Promise((resolve, reject) => {
		const chunks = [];
		let length = 0;
		req.on('data', (chunk) => {
			length += chunk.length;
			if (length > maxBody) { reject(new HttpError(413, 'Request body is too large.')); req.destroy(); return; }
			chunks.push(chunk);
		});
		req.on('end', () => {
			try {
				const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
				if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
				resolve(body);
			} catch { reject(new HttpError(400, 'Request body must be valid JSON.')); }
		});
		req.on('error', reject);
	});
}

async function postData(req, session, maxBody = MAX_BODY) {
	if (req.method !== 'POST') throw new HttpError(405, 'Use POST for this action.');
	const csrf = req.headers['x-csrf-token'];
	if (session?.csrfToken) {
		if (typeof csrf !== 'string' || csrf !== session.csrfToken) throw new HttpError(403, 'Your session expired. Refresh the page and try again.');
		return parseBody(req, maxBody);
	}
	if (typeof csrf === 'string' && csrf.length > 0) {
		return parseBody(req, maxBody);
	}
	return parseBody(req, maxBody);
}

function safeUser(user) {
	return { id: Number(user.id), username: String(user.username), name: String(user.full_name), role: String(user.role) };
}

function sessionUser(user) {
	return { ...safeUser(user), country: String(user.country || ''), countryCode: String(user.country_code || '') };
}

async function currentUser(session) {
	if (!session?.userId) return null;
	const user = await store.one('SELECT * FROM users WHERE id = ?', [session.userId]);
	if (!user || Number(user.auth_version) !== Number(session.authVersion)) return null;
	session.expiresAt = Date.now() + 30 * 60 * 1000;
	return user;
}

function validIdentity(username, name) {
	const length = [...name.trim()].length;
	return /^[a-zA-Z0-9._]{3,32}$/.test(username) && length >= 1 && length <= 80;
}

function validEmail(email, required = false) {
	if (!email || !email.trim()) return !required;
	const value = email.trim();
	return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function passwordMaterial(password, salt) {
	return crypto.createHmac('sha256', pepper()).update(`${password}#${salt}`, 'utf8').digest('hex');
}

async function createAccount(data, role, approvalStatus = 'approved', googleSub = null) {
	const username = String(data.username || '').trim();
	const name = String(data.name || '').trim();
	const email = String(data.email || '').trim();
	const country = countryName(data.countryCode);
	const countryCode = country ? String(data.countryCode).trim().toUpperCase() : '';
	const password = String(data.password || '');
	if (!validIdentity(username, name) || !validEmail(email) || Buffer.byteLength(password) < 12 || Buffer.byteLength(password) > 1024) throw new HttpError(422, 'Enter a valid name, username, email, and password of at least 12 characters.');
	const salt = `${username}#${crypto.randomBytes(16).toString('hex')}`;
	const approvedAt = approvalStatus === 'approved' ? new Date().toISOString() : null;
	const approvalDueAt = approvalStatus === 'pending' ? new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() : null;
	try {
		const result = await store.one('INSERT INTO users (username, full_name, role, password_salt, password_hash, email, google_sub, country, country_code, approval_status, approval_due_at, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *', [username, name, role, salt, bcrypt.hashSync(passwordMaterial(password, salt), 12), email || null, googleSub, country, countryCode, approvalStatus, approvalDueAt, approvedAt]);
		return result;
	} catch (error) {
		if (String(error.code || '').includes('CONSTRAINT') || error.code === '23505' || /UNIQUE constraint failed/i.test(error.message)) throw new HttpError(409, 'That username or email is already in use.');
		throw error;
	}
}

async function administratorEmail() {
	if (process.env.ADMIN_EMAIL) return process.env.ADMIN_EMAIL.trim();
	const administrator = await store.one("SELECT email FROM users WHERE role = 'admin' AND email IS NOT NULL ORDER BY id LIMIT 1");
	return String(administrator?.email || '').trim();
}

async function sendNotice(to, notice) {
	return mail.sendEmail(to, notice.subject, notice.text, notice.html);
}

function recoveryCodeHash(userId, code) {
	return crypto.createHmac('sha256', pepper()).update(`password-recovery:${userId}:${code}`, 'utf8').digest('hex');
}

async function requestPasswordRecovery(identity) {
	if (!mail.emailConfigured()) throw new HttpError(503, 'Password recovery email is not configured. Contact the administrator.');
	const account = await store.one(
		"SELECT id, username, full_name, email FROM users WHERE (username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE) AND approval_status = 'approved' LIMIT 1",
		[identity, identity]
	);
	if (!account || !validEmail(account.email, true)) return;

	const userId = Number(account.id);
	const now = Math.floor(Date.now() / 1000);
	const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
	const codeHash = recoveryCodeHash(userId, code);
	const allowed = await store.transaction(async (tx) => {
		const existing = await tx.one('SELECT requested_at, window_started_at, send_count FROM password_recovery WHERE user_id = ?', [userId]);
		if (existing && now - Number(existing.requested_at) < 60) return false;
		if (existing && now - Number(existing.window_started_at) < 3600 && Number(existing.send_count) >= 5) return false;
		const withinSendWindow = existing && now - Number(existing.window_started_at) < 3600;
		const windowStartedAt = withinSendWindow ? Number(existing.window_started_at) : now;
		const sendCount = withinSendWindow ? Number(existing.send_count) + 1 : 1;
		await tx.run(
			`INSERT INTO password_recovery (user_id, code_hash, expires_at, attempts, requested_at, window_started_at, send_count)
			VALUES (?, ?, ?, 0, ?, ?, ?)
			ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at,
			attempts = 0, requested_at = excluded.requested_at, window_started_at = excluded.window_started_at,
			send_count = excluded.send_count`,
			[userId, codeHash, now + 600, now, windowStartedAt, sendCount]
		);
		return true;
	});
	if (!allowed) return;

	const sent = await sendNotice(account.email, mail.recoveryCodeNotice(account, code));
	if (!sent) {
		console.error('Password recovery email could not be delivered.');
	}
}

async function resetPasswordWithRecovery(identity, code, newPassword) {
	const now = Math.floor(Date.now() / 1000);
	const result = await store.transaction(async (tx) => {
		const account = await tx.one(
			"SELECT id, username FROM users WHERE (username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE) AND approval_status = 'approved' LIMIT 1",
			[identity, identity]
		);
		if (!account) return false;
		const userId = Number(account.id);
		const recovery = await tx.one('SELECT code_hash, expires_at, attempts FROM password_recovery WHERE user_id = ?', [userId]);
		if (!recovery || Number(recovery.expires_at) <= now || Number(recovery.attempts) >= 5) return false;

		const expected = Buffer.from(recoveryCodeHash(userId, code), 'hex');
		const actual = Buffer.from(String(recovery.code_hash), 'hex');
		const valid = actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
		if (!valid) {
			const attempts = Number(recovery.attempts) + 1;
			if (attempts >= 5) await tx.run('UPDATE password_recovery SET attempts = ?, expires_at = ? WHERE user_id = ?', [attempts, now, userId]);
			else await tx.run('UPDATE password_recovery SET attempts = ? WHERE user_id = ?', [attempts, userId]);
			return false;
		}

		const passwordSalt = `${account.username}#${crypto.randomBytes(16).toString('hex')}`;
		const passwordHash = bcrypt.hashSync(passwordMaterial(newPassword, passwordSalt), 12);
		await tx.run(
			'UPDATE users SET password_salt = ?, password_hash = ?, failed_attempts = 0, locked_until = 0, auth_version = auth_version + 1 WHERE id = ?',
			[passwordSalt, passwordHash, userId]
		);
		await tx.run('UPDATE password_recovery SET attempts = 5, expires_at = ? WHERE user_id = ?', [now, userId]);
		return true;
	});
	if (!result) throw new HttpError(400, 'The verification code is invalid or expired. Request a new code and try again.');
}

async function requestViewerAccess(data, googleSub = null) {
	const admins = await store.one("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'");
	if (Number(admins.count) < 1) throw new HttpError(409, 'Sign-up will be available after the initial admin account is set up.');
	data.email = String(data.email || '').trim().toLowerCase();
	if (!validEmail(data.email, true)) throw new HttpError(422, 'Enter a valid name, username, email, and password of at least 12 characters.');
	if (!countryName(data.countryCode)) throw new HttpError(422, 'Choose the country you are joining from before requesting an account.');
	const adminEmail = await administratorEmail();
	if (process.env.NODE_ENV === 'production' && (!mail.emailConfigured() || !adminEmail)) throw new HttpError(503, 'Email delivery is not configured. Ask the administrator to finish email setup before creating an account.');
	const created = await createAccount(data, 'viewer', 'pending', googleSub);
	const [emailSent, adminNotified] = await Promise.all([
		sendNotice(created.email, mail.requestReceived(created)),
		adminEmail ? sendNotice(adminEmail, mail.adminRequestNotice(created)) : false,
	]);
	return { emailSent, adminNotified };
}

function googleOAuthClient() {
	if (!process.env.GOOGLE_CLIENT_ID) throw new HttpError(503, 'Google sign-in is not configured. Ask the administrator to configure it.');
	googleClient ||= new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
	return googleClient;
}

async function finishSignIn(req, res, user) {
	const session = newSession();
	session.userId = Number(user.id);
	session.authVersion = Number(user.auth_version || 0);
	await store.run("INSERT INTO account_activity (user_id, username, event) VALUES (?, ?, 'sign_in')", [user.id, user.username]);
	json(res, 200, { user: sessionUser(user), csrfToken: session.csrfToken }, { 'Set-Cookie': cookie(req, session) });
}

async function autoApproveDueRequests() {
	const now = new Date().toISOString();
	const due = await store.all("UPDATE users SET approval_status = 'approved', approved_at = ? WHERE approval_status = 'pending' AND approval_due_at IS NOT NULL AND approval_due_at <= ? RETURNING full_name, email", [now, now]);
	for (const account of due) {
		if (account.email) await sendNotice(account.email, mail.reviewNotice(account, true));
	}
}

class HttpError extends Error {
	constructor(status, message) { super(message); this.status = status; }
}

async function route(req, res, url, session) {
	const action = url.searchParams.get('action') || '';
	let data;
	if (action === 'state' && req.method === 'GET') {
		const user = await currentUser(session);
		const active = user ? session : (session || newSession());
		if (process.env.GOOGLE_CLIENT_ID) active.googleNonce = crypto.randomBytes(32).toString('base64url');
		const count = await store.one('SELECT COUNT(*) AS count FROM users');
		if (!backupAttempted && !store.REMOTE) {
			backupAttempted = true;
			pepper();
			store.startLocalBackupSchedule();
		}
		return json(res, 200, { csrfToken: active.csrfToken, setupRequired: Number(count.count) === 0, googleClientId: process.env.GOOGLE_CLIENT_ID || '', googleNonce: active.googleNonce || '', emailRecoveryAvailable: mail.emailConfigured(), countries: countryOptions(), user: user ? sessionUser(user) : null }, { 'Set-Cookie': cookie(req, active) });
	}
	if (action === 'setup') {
		data = await postData(req, session);
		const count = await store.one('SELECT COUNT(*) AS count FROM users');
		if (Number(count.count) !== 0) throw new HttpError(409, 'Initial setup is already complete.');
		return finishSignIn(req, res, await createAccount(data, 'admin'));
	}
	if (action === 'signup') {
		data = await postData(req, session);
		const { emailSent, adminNotified } = await requestViewerAccess(data);
		return json(res, 202, {
			message: 'Your request was submitted. An administrator can approve it sooner; if no decision is made, access is approved automatically after 24 hours.',
			emailSent,
			adminNotified,
		});
	}
	if (action === 'request-recovery-code') {
		data = await postData(req, session);
		const identity = String(data.identity || '').trim().toLowerCase();
		if (!identity || identity.length > 254) throw new HttpError(422, 'Enter the email address or username for your account.');
		await requestPasswordRecovery(identity);
		return json(res, 202, {
			message: 'If an approved account matches that email or username and has an email address, a verification code has been sent. The code expires in 10 minutes.',
		});
	}
	if (action === 'recover-password') {
		data = await postData(req, session);
		const identity = String(data.identity || '').trim().toLowerCase();
		const code = String(data.code || '').trim();
		const newPassword = String(data.newPassword || '');
		if (!identity || identity.length > 254) throw new HttpError(422, 'Enter the email address or username for your account.');
		if (!/^\d{6}$/.test(code)) throw new HttpError(422, 'Enter the six-digit verification code.');
		if (newPassword !== String(data.confirmPassword || '')) throw new HttpError(422, 'The new passwords do not match.');
		if (Buffer.byteLength(newPassword) < 12 || Buffer.byteLength(newPassword) > 1024) {
			throw new HttpError(422, 'Choose a new password between 12 and 1024 bytes.');
		}
		await resetPasswordWithRecovery(identity, code, newPassword);
		return json(res, 200, { message: 'Your password has been reset. Sign in with your new password.' });
	}
	if (action === 'google-login') {
		data = await postData(req, session);
		const credential = String(data.credential || '');
		if (!credential || credential.length > 8192) throw new HttpError(422, 'Google did not provide a valid sign-in credential.');
		const verifier = googleOAuthClient();
		let payload;
		try {
			const ticket = await verifier.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
			payload = ticket.getPayload();
		} catch (error) {
			console.error('Google credential verification failed:', error.message);
			throw new HttpError(401, 'Google could not verify this sign-in. Please try again.');
		}
		if (!payload?.sub || !payload.email || (payload.email_verified !== true && payload.email_verified !== 'true')) {
			throw new HttpError(401, 'Use a Google account with a verified email address.');
		}
		if (!session?.googleNonce || payload.nonce !== session.googleNonce) throw new HttpError(401, 'This Google sign-in has expired. Please try again.');
		const email = String(payload.email).trim().toLowerCase();
		if (!validEmail(email, true)) throw new HttpError(401, 'Google returned an invalid email address.');
		const linkedAccount = await store.one('SELECT * FROM users WHERE google_sub = ?', [String(payload.sub)]);
		if (linkedAccount) {
			if (linkedAccount.approval_status !== 'approved') {
				throw new HttpError(403, linkedAccount.approval_status === 'pending' ? 'Your Google account request is waiting for administrator approval.' : 'This Google account request was declined. Contact the administrator.');
			}
			if (linkedAccount.totp_secret) throw new HttpError(403, 'This account requires an authenticator code. Sign in with your username and password to complete two-step verification.');
			return finishSignIn(req, res, linkedAccount);
		}
		const emailAccount = await store.one('SELECT id FROM users WHERE email = ? COLLATE NOCASE', [email]);
		if (emailAccount) throw new HttpError(409, 'An account already uses this email. Sign in with that account or contact the administrator to link Google sign-in.');
		const prefix = email.split('@')[0].replace(/[^a-zA-Z0-9._]/g, '').slice(0, 21) || 'google';
		const username = `${prefix}_${crypto.randomBytes(5).toString('hex')}`;
		const name = (String(payload.name || '').trim() || prefix).slice(0, 80);
		const { emailSent, adminNotified } = await requestViewerAccess({
			username,
			name,
			email,
			countryCode: String(data.countryCode || ''),
			password: crypto.randomBytes(32).toString('base64url'),
		}, String(payload.sub));
		session.googleNonce = crypto.randomBytes(32).toString('base64url');
		return json(res, 202, {
			pendingApproval: true,
			message: 'Your Google account request was submitted and is waiting for administrator review.',
			emailSent,
			adminNotified,
		}, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'login') {
		data = await postData(req, session);
		const identity = String(data.username || '').trim();
		const user = await store.one('SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1', [identity, identity]);
		const now = Math.floor(Date.now() / 1000);
		if (!user || Number(user.locked_until) > now) throw new HttpError(401, 'Username or password is incorrect, or sign-in is temporarily locked.');
		const password = String(data.password || '');
		if (!bcrypt.compareSync(passwordMaterial(password, user.password_salt), user.password_hash)) {
			const failures = Number(user.failed_attempts) + 1;
			await store.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?', [failures, failures >= 5 ? now + 900 : 0, user.id]);
			throw new HttpError(401, 'Username or password is incorrect, or sign-in is temporarily locked.');
		}
		if (bcrypt.getRounds(user.password_hash) < 12) {
			await store.run('UPDATE users SET password_hash = ? WHERE id = ?', [bcrypt.hashSync(passwordMaterial(password, user.password_salt), 12), user.id]);
		}
		if (user.approval_status && user.approval_status !== 'approved') {
			throw new HttpError(403, user.approval_status === 'pending' ? 'Your account is waiting for administrator approval.' : 'This account is not approved for sign-in.');
		}
		if (user.totp_secret) {
			const totpSecret = decryptTotpSecret(user.totp_secret);
			const matchedStep = matchingTotpStep(totpSecret, data.totpCode);
			if (matchedStep === null) {
				if (!data.totpCode) return json(res, 200, { requiresTwoFactor: true, message: 'Enter the six-digit code from your authenticator app.' });
				await store.run('UPDATE users SET failed_attempts = failed_attempts + 1, locked_until = CASE WHEN failed_attempts + 1 >= 5 THEN ? ELSE 0 END WHERE id = ?', [now + 900, user.id]);
				throw new HttpError(401, 'The authenticator code is incorrect or expired.');
			}
			const accepted = await store.run('UPDATE users SET last_totp_step = ?, failed_attempts = 0, locked_until = 0 WHERE id = ? AND last_totp_step < ?', [matchedStep, user.id, matchedStep]);
			if (!accepted.rowsAffected) throw new HttpError(401, 'That authenticator code has already been used. Wait for the next code and try again.');
		} else if (data.totpCode) {
			throw new HttpError(401, 'Authenticator verification is not enabled for this account.');
		} else {
			await store.run('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?', [user.id]);
		}
		return finishSignIn(req, res, user);
	}
	if (action === 'account' && req.method === 'GET') {
		const user = await currentUser(session);
		if (!user) throw new HttpError(401, 'Please sign in again.');
		return json(res, 200, { user: sessionUser(user), email: String(user.email || ''), twoFactorEnabled: Boolean(user.totp_secret) }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'community' && req.method === 'GET') {
		const user = await currentUser(session);
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const today = new Date().toISOString().slice(0, 10);
		const [posts, replies, gigs, musicians, profile, tracks, comments, messages, listings] = await Promise.all([
			store.all("SELECT p.id, p.author_id, p.kind, p.body, p.created_at, u.username, u.full_name FROM music_posts p JOIN users u ON u.id = p.author_id WHERE u.approval_status = 'approved' ORDER BY p.created_at DESC, p.id DESC LIMIT 60"),
			store.all("SELECT r.id, r.post_id, r.author_id, r.body, r.created_at, u.username, u.full_name FROM music_post_replies r JOIN users u ON u.id = r.author_id JOIN music_posts p ON p.id = r.post_id WHERE u.approval_status = 'approved' AND p.author_id IN (SELECT id FROM users WHERE approval_status = 'approved') ORDER BY r.created_at, r.id LIMIT 500"),
			store.all("SELECT g.id, g.poster_id, g.title, g.location, g.event_date, g.description, g.contact_email, g.opportunity_type, g.compensation, g.created_at, u.username, u.full_name FROM gig_listings g JOIN users u ON u.id = g.poster_id WHERE g.event_date >= ? AND u.approval_status = 'approved' ORDER BY g.event_date, g.id DESC LIMIT 60", [today]),
			store.all("SELECT u.id, u.username, u.full_name, p.location, p.country, p.member_type, p.instruments, p.genres, p.bio, p.contact_email, p.avatar_preset, CASE WHEN p.avatar_data IS NULL THEN 0 ELSE 1 END AS has_avatar, p.share_location, CASE WHEN p.share_location = 1 THEN p.latitude END AS latitude, CASE WHEN p.share_location = 1 THEN p.longitude END AS longitude FROM users u LEFT JOIN musician_profiles p ON p.user_id = u.id WHERE u.approval_status = 'approved' ORDER BY CASE WHEN u.id = ? THEN 0 ELSE 1 END, u.full_name COLLATE NOCASE LIMIT 150", [user.id]),
			store.one('SELECT location, country, member_type, instruments, genres, bio, contact_email, avatar_preset, CASE WHEN avatar_data IS NULL THEN 0 ELSE 1 END AS has_avatar, share_location, latitude, longitude, language FROM musician_profiles WHERE user_id = ?', [user.id]),
			store.all("SELECT t.id, t.title, t.genre, t.note, t.audio_url, t.media_type, CASE WHEN t.audio_data IS NULL THEN 0 ELSE 1 END AS has_upload, t.created_at, u.username, u.full_name, (SELECT COUNT(*) FROM music_track_likes l WHERE l.track_id = t.id) AS like_count, EXISTS(SELECT 1 FROM music_track_likes l WHERE l.track_id = t.id AND l.user_id = ?) AS liked FROM music_tracks t JOIN users u ON u.id = t.author_id WHERE u.approval_status = 'approved' ORDER BY t.created_at DESC, t.id DESC LIMIT 50", [user.id]),
			store.all("SELECT c.id, c.track_id, c.body, c.created_at, u.username, u.full_name FROM music_track_comments c JOIN users u ON u.id = c.author_id WHERE u.approval_status = 'approved' ORDER BY c.created_at DESC, c.id DESC LIMIT 200"),
			store.all("SELECT m.id, m.room, m.body, m.created_at, u.id AS author_id, u.username, u.full_name FROM community_messages m JOIN users u ON u.id = m.author_id WHERE u.approval_status = 'approved' ORDER BY m.created_at DESC, m.id DESC LIMIT 250"),
			store.all("SELECT m.id, m.seller_id, m.title, m.category, m.price, m.price_amount, m.currency, m.stock, m.location, m.description, m.contact_email, CASE WHEN m.image_data IS NULL THEN 0 ELSE 1 END AS has_image, m.created_at, u.username, u.full_name FROM marketplace_listings m JOIN users u ON u.id = m.seller_id WHERE u.approval_status = 'approved' ORDER BY m.created_at DESC, m.id DESC LIMIT 100"),
		]);
		return json(res, 200, { posts, replies, gigs, musicians, tracks, comments, messages: messages.reverse(), listings, profile: profile || {}, user: sessionUser(user) }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'member-avatar' && req.method === 'GET') {
		if (!await currentUser(session)) throw new HttpError(401, 'Please sign in again.');
		const id = Number(url.searchParams.get('id'));
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(404, 'Profile image not found.');
		const profile = await store.one('SELECT avatar_data, avatar_mime FROM musician_profiles WHERE user_id = ?', [id]);
		if (!profile?.avatar_data) throw new HttpError(404, 'Profile image not found.');
		const image = Buffer.from(profile.avatar_data);
		const type = ['image/jpeg', 'image/png', 'image/webp'].includes(String(profile.avatar_mime)) ? String(profile.avatar_mime) : 'application/octet-stream';
		res.writeHead(200, { 'Content-Type': type, 'Content-Length': image.length, 'Cache-Control': 'private, max-age=300', 'X-Content-Type-Options': 'nosniff' });
		res.end(image);
		return;
	}
	if (action === 'marketplace-image' && req.method === 'GET') {
		if (!await currentUser(session)) throw new HttpError(401, 'Please sign in again.');
		const id = Number(url.searchParams.get('id'));
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(404, 'Listing image not found.');
		const listing = await store.one('SELECT image_data, image_mime FROM marketplace_listings WHERE id = ?', [id]);
		if (!listing?.image_data) throw new HttpError(404, 'Listing image not found.');
		const image = Buffer.from(listing.image_data);
		const type = ['image/jpeg', 'image/png', 'image/webp'].includes(String(listing.image_mime)) ? String(listing.image_mime) : 'application/octet-stream';
		res.writeHead(200, { 'Content-Type': type, 'Content-Length': image.length, 'Cache-Control': 'private, max-age=300', 'X-Content-Type-Options': 'nosniff' });
		res.end(image);
		return;
	}
	if (action === 'community-message-audio' && req.method === 'GET') {
		if (!await currentUser(session)) throw new HttpError(401, 'Please sign in again.');
		const id = Number(url.searchParams.get('id'));
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(404, 'Voice message not found.');
		const message = await store.one('SELECT audio_data, audio_mime FROM community_messages WHERE id = ?', [id]);
		if (!message?.audio_data) throw new HttpError(404, 'Voice message not found.');
		const audio = Buffer.from(message.audio_data);
		const type = ['audio/webm', 'audio/ogg', 'audio/mp4'].includes(String(message.audio_mime)) ? String(message.audio_mime) : 'application/octet-stream';
		res.writeHead(200, { 'Content-Type': type, 'Content-Length': audio.length, 'Cache-Control': 'private, max-age=300', 'X-Content-Type-Options': 'nosniff' });
		res.end(audio);
		return;
	}
	if (action === 'community-call-config' && req.method === 'GET') {
		const user = await currentUser(session);
		if (!user) throw new HttpError(401, 'Please sign in again.');
		return json(res, 200, createIceServers(user.id), { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'community-call-inbox' && req.method === 'GET') {
		const user = await currentUser(session);
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const now = new Date().toISOString();
		await store.run("UPDATE community_calls SET status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE status IN ('ringing', 'active') AND expires_at <= ?", [now]);
		const calls = await store.all("SELECT c.id, c.room, c.caller_id, c.media_type, c.created_at, u.full_name AS caller_name FROM community_calls c JOIN users u ON u.id = c.caller_id WHERE c.recipient_id = ? AND c.status = 'ringing' AND u.approval_status = 'approved' ORDER BY c.created_at DESC LIMIT 5", [user.id]);
		return json(res, 200, { calls }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'community-call-events' && req.method === 'GET') {
		const user = await currentUser(session);
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const callId = String(url.searchParams.get('callId') || '');
		const after = Number(url.searchParams.get('after') || 0);
		if (!/^[0-9a-f-]{36}$/i.test(callId) || !Number.isSafeInteger(after) || after < 0) throw new HttpError(422, 'Choose a valid call.');
		const call = await store.one('SELECT id, caller_id, recipient_id, media_type, status, expires_at FROM community_calls WHERE id = ? AND (caller_id = ? OR recipient_id = ?)', [callId, user.id, user.id]);
		if (!call) throw new HttpError(404, 'That call is no longer available.');
		if (['ringing', 'active'].includes(String(call.status)) && Date.parse(String(call.expires_at)) <= Date.now()) {
			await store.run("UPDATE community_calls SET status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status IN ('ringing', 'active')", [callId]);
			call.status = 'expired';
		}
		const signals = await store.all('SELECT id, sender_id, signal_type, payload FROM community_call_signals WHERE call_id = ? AND id > ? AND sender_id <> ? ORDER BY id LIMIT 100', [callId, after, user.id]);
		return json(res, 200, { call, signals: signals.map((signal) => ({ ...signal, payload: JSON.parse(String(signal.payload)) })) }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'marketplace-orders' && req.method === 'GET') {
		const user = await currentUser(session);
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const [sellerOrders, buyerOrders] = await Promise.all([
			store.all('SELECT o.id, o.listing_id, o.quantity, o.amount_minor, o.currency, o.status, o.buyer_name, o.buyer_email, o.buyer_phone, o.delivery_address, o.delivery_note, o.created_at, m.title FROM marketplace_orders o JOIN marketplace_listings m ON m.id = o.listing_id WHERE o.seller_id = ? ORDER BY o.created_at DESC LIMIT 100', [user.id]),
			store.all('SELECT o.id, o.listing_id, o.quantity, o.amount_minor, o.currency, o.reference, o.status, o.created_at, m.title, u.full_name AS seller_name FROM marketplace_orders o JOIN marketplace_listings m ON m.id = o.listing_id JOIN users u ON u.id = o.seller_id WHERE o.buyer_id = ? ORDER BY o.created_at DESC LIMIT 100', [user.id]),
		]);
		return json(res, 200, { sellerOrders, buyerOrders }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'marketplace-verify' && req.method === 'GET') {
		const user = await currentUser(session);
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const reference = String(url.searchParams.get('reference') || '');
		if (!/^[A-Za-z0-9_-]{12,100}$/.test(reference)) throw new HttpError(422, 'Choose a valid payment reference.');
		const secret = process.env.PAYSTACK_SECRET_KEY || '';
		if (!secret) throw new HttpError(503, 'Paystack checkout is not configured. Ask the site administrator to set PAYSTACK_SECRET_KEY.');
		let response;
		try {
			response = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, { headers: { Authorization: `Bearer ${secret}`, Accept: 'application/json' } });
		} catch {
			throw new HttpError(502, 'Paystack could not be reached to verify this payment. Try again shortly.');
		}
		let verification;
		try { verification = await response.json(); } catch { throw new HttpError(502, 'Paystack returned an invalid payment verification response.'); }
		if (!response.ok || verification.status !== true || !verification.data) throw new HttpError(502, String(verification.message || 'Paystack could not verify this payment.'));
		const transaction = verification.data;
		if (String(transaction.status) !== 'success') return json(res, 200, { paid: false, message: 'Payment is not complete yet. Finish payment or try verifying again.' }, { 'Set-Cookie': cookie(req, session) });
		const result = await store.transaction(async (tx) => {
			const order = await tx.one('SELECT id, listing_id, quantity, amount_minor, currency, status, inventory_issue FROM marketplace_orders WHERE reference = ? AND buyer_id = ?', [reference, user.id]);
			if (!order) throw new HttpError(404, 'The order for this payment could not be found.');
			if (Number(transaction.amount) !== Number(order.amount_minor) || String(transaction.currency || '').toUpperCase() !== String(order.currency).toUpperCase()) {
				throw new HttpError(409, 'The verified payment amount or currency does not match this order. Contact support before arranging delivery.');
			}
			if (order.status !== 'pending') return { paid: order.status !== 'cancelled', status: order.status, stockAvailable: Number(order.inventory_issue) === 0 };
			const claimed = await tx.one("UPDATE marketplace_orders SET status = 'paid', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending' RETURNING id", [order.id]);
			if (!claimed) {
				const latest = await tx.one('SELECT status, inventory_issue FROM marketplace_orders WHERE id = ?', [order.id]);
				return { paid: latest?.status !== 'cancelled', status: String(latest?.status || 'pending'), stockAvailable: Number(latest?.inventory_issue || 0) === 0 };
			}
			const inventory = await tx.run('UPDATE marketplace_listings SET stock = stock - ? WHERE id = ? AND stock >= ?', [order.quantity, order.listing_id, order.quantity]);
			const stockAvailable = Number(inventory.rowsAffected) > 0;
			await tx.run('UPDATE marketplace_orders SET inventory_issue = ? WHERE id = ?', [stockAvailable ? 0 : 1, order.id]);
			return { paid: true, status: 'paid', stockAvailable };
		});
		const message = result.stockAvailable ? 'Payment confirmed. The seller will arrange delivery.' : 'Payment was received, but the item is no longer in stock. Contact the seller to arrange a refund.';
		return json(res, 200, { ...result, message }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'community-messages' && req.method === 'GET') {
		if (!await currentUser(session)) throw new HttpError(401, 'Please sign in again.');
		const room = String(url.searchParams.get('room') || '');
		if (!CHAT_ROOMS.has(room)) throw new HttpError(422, 'Choose a valid community room.');
		const messages = await store.all("SELECT m.id, m.room, m.body, CASE WHEN m.audio_data IS NULL THEN 0 ELSE 1 END AS has_audio, m.created_at, u.id AS author_id, u.username, u.full_name FROM community_messages m JOIN users u ON u.id = m.author_id WHERE m.room = ? AND u.approval_status = 'approved' ORDER BY m.created_at DESC, m.id DESC LIMIT 100", [room]);
		return json(res, 200, { messages: messages.reverse() }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'community-room-summaries' && req.method === 'GET') {
		if (!await currentUser(session)) throw new HttpError(401, 'Please sign in again.');
		const summaries = await store.all("SELECT m.room, COUNT(*) AS message_count FROM community_messages m JOIN users u ON u.id = m.author_id WHERE u.approval_status = 'approved' GROUP BY m.room");
		const counts = new Map(summaries.map(({ room, message_count }) => [room, Number(message_count)]));
		const rooms = ['singers', 'instrumentalists', 'marketplace', 'support'].map((room) => ({ room, message_count: counts.get(room) || 0 }));
		return json(res, 200, { rooms }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'admin-activity' && req.method === 'GET') {
		const admin = await currentUser(session);
		if (!admin) throw new HttpError(401, 'Please sign in again.');
		if (admin.role !== 'admin') throw new HttpError(403, 'Only an admin can view account activity.');
		const activity = await store.all('SELECT a.id, a.user_id, a.username, a.event, a.occurred_at, u.full_name FROM account_activity a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.occurred_at DESC, a.id DESC LIMIT 500');
		return json(res, 200, { activity }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'community-audio' && req.method === 'GET') {
		if (!await currentUser(session)) throw new HttpError(401, 'Please sign in again.');
		const id = Number(url.searchParams.get('id'));
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(404, 'Audio track not found.');
		const track = await store.one('SELECT audio_data, audio_mime FROM music_tracks WHERE id = ?', [id]);
		if (!track?.audio_data) throw new HttpError(404, 'Uploaded audio was not found.');
		const audio = Buffer.from(track.audio_data);
		const type = ['audio/mpeg', 'audio/mp4', 'audio/ogg', 'audio/wav', 'audio/webm'].includes(String(track.audio_mime)) ? String(track.audio_mime) : 'application/octet-stream';
		const range = /^bytes=(\d*)-(\d*)$/.exec(String(req.headers.range || ''));
		let start = 0;
		let end = audio.length - 1;
		let status = 200;
		if (range) {
			if (!range[1] && !range[2]) throw new HttpError(416, 'Invalid audio range.');
			if (!range[1]) start = Math.max(0, audio.length - Number(range[2]));
			else start = Number(range[1]);
			if (range[2] && range[1]) end = Math.min(end, Number(range[2]));
			if (start >= audio.length || end < start) throw new HttpError(416, 'Audio range is not available.');
			status = 206;
		}
		const part = audio.subarray(start, end + 1);
		res.writeHead(status, { 'Content-Type': type, 'Content-Length': part.length, 'Accept-Ranges': 'bytes', ...(status === 206 ? { 'Content-Range': `bytes ${start}-${end}/${audio.length}` } : {}), 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' });
		res.end(part);
		return;
	}
	if (action === 'users' && req.method === 'GET') {
		const user = await currentUser(session);
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.role !== 'admin') throw new HttpError(403, 'Only an admin can view the account directory.');
		const users = await store.all("SELECT u.id, u.username, u.full_name, u.role, u.email, u.country, u.country_code, u.created_at, u.approved_at, (SELECT MAX(a.occurred_at) FROM account_activity a WHERE a.user_id = u.id AND a.event = 'sign_in') AS last_sign_in, (SELECT MAX(a.occurred_at) FROM account_activity a WHERE a.user_id = u.id AND a.event = 'sign_out') AS last_sign_out, p.member_type, CASE WHEN p.avatar_data IS NULL THEN 0 ELSE 1 END AS has_avatar FROM users u LEFT JOIN musician_profiles p ON p.user_id = u.id WHERE u.approval_status = 'approved' ORDER BY u.full_name COLLATE NOCASE");
		return json(res, 200, { user: safeUser(user), email: String(user.email || ''), users: users.map((account) => ({ ...safeUser(account), email: String(account.email || ''), country: String(account.country || ''), countryCode: String(account.country_code || '') || countryCodeForName(account.country) })) }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'approvals' && req.method === 'GET') {
		const user = await currentUser(session);
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.role !== 'admin') throw new HttpError(403, 'Only an admin can review access requests.');
		const requests = await store.all("SELECT id, username, full_name, email, country, country_code, created_at, approval_due_at FROM users WHERE approval_status = 'pending' ORDER BY created_at, id");
		const stats = await store.one("SELECT COUNT(*) AS total, SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) AS admins FROM users WHERE approval_status = 'approved'");
		return json(res, 200, { requests: requests.map((request) => ({ ...request, country_code: String(request.country_code || '') || countryCodeForName(request.country) })), totalMembers: Number(stats.total || 0), administrators: Number(stats.admins || 0) }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'signature-keys' && req.method === 'GET') {
		if (!await currentUser(session)) throw new HttpError(401, 'Please sign in again.');
		const rows = await store.all('SELECT username, signature_public_key FROM users WHERE signature_public_key IS NOT NULL');
		const keys = Object.fromEntries(rows.map((row) => [String(row.username), String(row.signature_public_key)]));
		return json(res, 200, { keys }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'logout') {
		await postData(req, session);
		const signingOut = await currentUser(session);
		if (signingOut) await store.run("INSERT INTO account_activity (user_id, username, event) VALUES (?, ?, 'sign_out')", [signingOut.id, signingOut.username]);
		return json(res, 200, { message: 'Signed out.' }, { 'Set-Cookie': `${SESSION_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${process.env.NODE_ENV === 'production' ? '; Secure' : ''}` });
	}
	if (action === 'deleted-users' && req.method === 'GET') {
		const delUser = await currentUser(session);
		if (!delUser) throw new HttpError(401, 'Please sign in again.');
		if (delUser.role !== 'admin') throw new HttpError(403, 'Only an admin can view the deleted accounts archive.');
		const deletedUsers = await store.all('SELECT id, original_id, username, full_name, role, email, country, country_code, approval_status, created_at, approved_at, deleted_at, deleted_by_username FROM deleted_users ORDER BY deleted_at DESC');
		return json(res, 200, { deletedUsers }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'list-backups' && req.method === 'GET') {
		const lbUser = await currentUser(session);
		if (!lbUser) throw new HttpError(401, 'Please sign in again.');
		if (lbUser.role !== 'admin') throw new HttpError(403, 'Only an admin can list backups.');
		if (store.REMOTE) return json(res, 200, { backups: [], remote: true }, { 'Set-Cookie': cookie(req, session) });
		const backups = store.listBackups();
		return json(res, 200, { backups }, { 'Set-Cookie': cookie(req, session) });
	}
	data = await postData(req, session, action === 'community-track' ? MAX_TRACK_BODY : action === 'update-musician-profile' ? MAX_PROFILE_BODY : action === 'marketplace-listing' ? MAX_MARKET_BODY : action === 'community-voice' ? MAX_CHAT_AUDIO_BODY : MAX_BODY);
	const user = await currentUser(session);
	if (action === 'begin-two-factor') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.totp_secret) throw new HttpError(409, 'Two-step verification is already enabled.');
		const secret = encodeBase32(crypto.randomBytes(20));
		await store.run('UPDATE users SET totp_pending_secret = ? WHERE id = ?', [encryptTotpSecret(secret), user.id]);
		const label = encodeURIComponent(`Musicians World:${user.username}`);
		const issuer = encodeURIComponent('Musicians World');
		const otpauthUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
		return json(res, 200, { secret, otpauthUrl, message: 'Add this account to your authenticator app, then enter its six-digit code to enable verification.' });
	}
	if (action === 'enable-two-factor') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.totp_secret) throw new HttpError(409, 'Two-step verification is already enabled.');
		const pending = await store.one('SELECT totp_pending_secret FROM users WHERE id = ?', [user.id]);
		if (!pending?.totp_pending_secret) throw new HttpError(409, 'Start authenticator setup again to get a fresh setup key.');
		const pendingSecret = decryptTotpSecret(pending.totp_pending_secret);
		const step = matchingTotpStep(pendingSecret, data.code);
		if (step === null) throw new HttpError(422, 'That code did not match. Check your authenticator and try again.');
		await store.run('UPDATE users SET totp_secret = ?, totp_pending_secret = NULL, last_totp_step = ? WHERE id = ?', [encryptTotpSecret(pendingSecret), step, user.id]);
		return json(res, 200, { message: 'Two-step verification is enabled for this account.' });
	}
	if (action === 'disable-two-factor') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (!user.totp_secret) throw new HttpError(409, 'Two-step verification is not enabled.');
		const password = String(data.password || '');
		if (!bcrypt.compareSync(passwordMaterial(password, user.password_salt), user.password_hash)) throw new HttpError(403, 'Your password is incorrect.');
		const step = matchingTotpStep(decryptTotpSecret(user.totp_secret), data.code);
		if (step === null || step <= Number(user.last_totp_step)) throw new HttpError(422, 'Enter a fresh authenticator code that has not been used yet.');
		const disabled = await store.run('UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL, last_totp_step = -1 WHERE id = ? AND last_totp_step < ?', [user.id, step]);
		if (!disabled.rowsAffected) throw new HttpError(409, 'The authenticator settings changed. Refresh the page and try again.');
		return json(res, 200, { message: 'Two-step verification has been turned off.' });
	}
	if (action === 'community-post') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const kind = String(data.kind || 'idea');
		const body = String(data.body || '').trim();
		if (!['idea', 'collab'].includes(kind)) throw new HttpError(422, 'Choose an idea or collaboration post.');
		if (!body || [...body].length > 1200) throw new HttpError(422, 'Write a post between 1 and 1200 characters.');
		await store.run('INSERT INTO music_posts (author_id, kind, body) VALUES (?, ?, ?)', [user.id, kind, body]);
		return json(res, 201, { message: 'Your post is live in the community.' });
	}
	if (action === 'community-post-edit') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const id = Number(data.id);
		const body = String(data.body || '').trim();
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(422, 'Choose a valid post.');
		if (!body || [...body].length > 1200) throw new HttpError(422, 'Write a post between 1 and 1200 characters.');
		const result = await store.run('UPDATE music_posts SET body = ? WHERE id = ? AND author_id = ?', [body, id, user.id]);
		if (!Number(result.rowsAffected || 0)) throw new HttpError(403, 'You can only edit your own post.');
		return json(res, 200, { message: 'Post updated.' });
	}
	if (action === 'community-post-delete') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const id = Number(data.id);
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(422, 'Choose a valid post.');
		const deleted = await store.transaction(async (tx) => {
			const post = await tx.one('SELECT id, author_id FROM music_posts WHERE id = ?', [id]);
			if (!post) return false;
			if (Number(post.author_id) !== Number(user.id) && user.role !== 'admin') throw new HttpError(403, 'You can only delete your own post.');
			await tx.run('DELETE FROM music_post_replies WHERE post_id = ?', [id]);
			await tx.run('DELETE FROM music_posts WHERE id = ?', [id]);
			return true;
		});
		if (!deleted) throw new HttpError(404, 'That post is no longer available.');
		return json(res, 200, { message: 'Post deleted.' });
	}
	if (action === 'community-reply') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const postId = Number(data.postId);
		const body = String(data.body || '').trim();
		if (!Number.isSafeInteger(postId) || postId < 1) throw new HttpError(422, 'Choose a valid post to reply to.');
		if (!body || [...body].length > 1200) throw new HttpError(422, 'Write a reply between 1 and 1200 characters.');
		const post = await store.one("SELECT p.id FROM music_posts p JOIN users u ON u.id = p.author_id WHERE p.id = ? AND u.approval_status = 'approved'", [postId]);
		if (!post) throw new HttpError(404, 'That post is no longer available.');
		await store.run('INSERT INTO music_post_replies (post_id, author_id, body) VALUES (?, ?, ?)', [postId, user.id, body]);
		return json(res, 201, { message: 'Reply added.' });
	}
	if (action === 'community-reply-edit') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const id = Number(data.id);
		const body = String(data.body || '').trim();
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(422, 'Choose a valid reply.');
		if (!body || [...body].length > 1200) throw new HttpError(422, 'Write a reply between 1 and 1200 characters.');
		const result = await store.run('UPDATE music_post_replies SET body = ? WHERE id = ? AND author_id = ?', [body, id, user.id]);
		if (!Number(result.rowsAffected || 0)) throw new HttpError(403, 'You can only edit your own reply.');
		return json(res, 200, { message: 'Reply updated.' });
	}
	if (action === 'community-reply-delete') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const id = Number(data.id);
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(422, 'Choose a valid reply.');
		const reply = await store.one('SELECT author_id FROM music_post_replies WHERE id = ?', [id]);
		if (!reply) throw new HttpError(404, 'That reply is no longer available.');
		if (Number(reply.author_id) !== Number(user.id) && user.role !== 'admin') throw new HttpError(403, 'You can only delete your own reply.');
		await store.run('DELETE FROM music_post_replies WHERE id = ?', [id]);
		return json(res, 200, { message: 'Reply deleted.' });
	}
	if (action === 'community-track') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const title = String(data.title || '').trim();
		const genre = String(data.genre || '').trim();
		const note = String(data.note || '').trim();
		const audioUrl = String(data.audioUrl || '').trim();
		const mediaType = String(data.mediaType || 'audio');
		const audioBase64 = String(data.audioBase64 || '');
		let audioData = null;
		let audioMime = null;
		let parsedUrl = null;
		if (!['audio', 'video'].includes(mediaType)) throw new HttpError(422, 'Choose audio or video media.');
		if (mediaType === 'video' && audioBase64) throw new HttpError(422, 'Video uploads are not supported yet. Use a public YouTube or Vimeo link.');
		if (audioBase64) {
			const mime = String(data.audioMime || '').toLowerCase();
			if (!['audio/mpeg', 'audio/mp4', 'audio/ogg', 'audio/wav', 'audio/webm'].includes(mime)) throw new HttpError(422, 'Choose an MP3, M4A, OGG, WAV, or WebM audio file.');
			if (audioBase64.length > Math.ceil(MAX_TRACK_AUDIO * 4 / 3) + 8 || !/^[A-Za-z0-9+/]*={0,2}$/.test(audioBase64)) throw new HttpError(413, 'Audio uploads must be 3 MB or smaller.');
			audioData = Buffer.from(audioBase64, 'base64');
			if (!audioData.length || audioData.length > MAX_TRACK_AUDIO || audioData.toString('base64') !== audioBase64) throw new HttpError(422, 'The audio file could not be read. Choose a valid audio file up to 3 MB.');
			const isValidAudio = mime === 'audio/ogg' ? audioData.subarray(0, 4).toString() === 'OggS'
				: mime === 'audio/wav' ? audioData.subarray(0, 4).toString() === 'RIFF' && audioData.subarray(8, 12).toString() === 'WAVE'
				: mime === 'audio/webm' ? audioData.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))
				: mime === 'audio/mp4' ? audioData.subarray(4, 8).toString() === 'ftyp'
				: audioData.subarray(0, 3).toString() === 'ID3' || [0xff, 0xfb, 0xf3, 0xf2].includes(audioData[0]) && (audioData[1] & 0xe0) === 0xe0;
			if (!isValidAudio) throw new HttpError(422, 'The uploaded file does not match its audio format.');
			audioMime = mime;
		} else {
			try { parsedUrl = new URL(audioUrl); } catch { throw new HttpError(422, 'Upload an audio file or add a valid public streaming link.'); }
			const host = parsedUrl.hostname.toLowerCase();
			const isAudioFile = /\.(mp3|m4a|ogg|oga|wav|webm|aac|flac)$/i.test(parsedUrl.pathname);
			const isSpotify = host === 'open.spotify.com' && /^\/(?:intl-[a-z]{2}\/)?(track|episode|album|playlist)\/[A-Za-z0-9]+\/?$/i.test(parsedUrl.pathname);
			const youtubeId = host === 'youtu.be' ? parsedUrl.pathname.slice(1).split('/')[0] : (parsedUrl.searchParams.get('v') || parsedUrl.pathname.match(/^\/(?:embed|shorts)\/([A-Za-z0-9_-]{11})/)?.[1] || '');
			const isYouTube = ['youtube.com', 'www.youtube.com', 'music.youtube.com', 'youtu.be'].includes(host) && /^[A-Za-z0-9_-]{11}$/.test(youtubeId);
			const isVimeo = ['vimeo.com', 'www.vimeo.com'].includes(host) && /^\/\d{6,12}\/?$/.test(parsedUrl.pathname);
			const isSoundCloud = ['soundcloud.com', 'www.soundcloud.com'].includes(host) && parsedUrl.pathname.split('/').filter(Boolean).length >= 2;
			if (parsedUrl.protocol !== 'https:' || parsedUrl.username || parsedUrl.password || (mediaType === 'video' ? !(isYouTube || isVimeo) : !(isAudioFile || isSpotify || isYouTube || isSoundCloud))) throw new HttpError(422, mediaType === 'video' ? 'Use a public HTTPS YouTube or Vimeo video link.' : 'Use an HTTPS audio link or upload an MP3, M4A, OGG, WAV, or WebM file.');
		}
		if (!title || [...title].length > 120 || [...genre].length > 80 || [...note].length > 500) throw new HttpError(422, 'Add a title (up to 120 characters), optional genre (up to 80), and note (up to 500).');
		await store.run('INSERT INTO music_tracks (author_id, title, genre, note, audio_url, media_type, audio_data, audio_mime) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [user.id, title, genre, note, parsedUrl?.toString() || '', mediaType, audioData, audioMime]);
		return json(res, 201, { message: 'Your track is ready for the community to hear.' });
	}
	if (action === 'community-like') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const trackId = Number(data.trackId);
		if (!Number.isSafeInteger(trackId) || trackId < 1) throw new HttpError(422, 'Choose a valid track.');
		const liked = await store.transaction(async (tx) => {
			if (!await tx.one('SELECT id FROM music_tracks WHERE id = ?', [trackId])) throw new HttpError(404, 'This track is no longer available.');
			const existing = await tx.one('SELECT track_id FROM music_track_likes WHERE track_id = ? AND user_id = ?', [trackId, user.id]);
			if (existing) { await tx.run('DELETE FROM music_track_likes WHERE track_id = ? AND user_id = ?', [trackId, user.id]); return false; }
			await tx.run('INSERT INTO music_track_likes (track_id, user_id) VALUES (?, ?)', [trackId, user.id]);
			return true;
		});
		return json(res, 200, { liked });
	}
	if (action === 'community-comment') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const trackId = Number(data.trackId);
		const body = String(data.body || '').trim();
		if (!Number.isSafeInteger(trackId) || trackId < 1 || !body || [...body].length > 500) throw new HttpError(422, 'Write a comment of up to 500 characters.');
		if (!await store.one('SELECT id FROM music_tracks WHERE id = ?', [trackId])) throw new HttpError(404, 'This track is no longer available.');
		await store.run('INSERT INTO music_track_comments (track_id, author_id, body) VALUES (?, ?, ?)', [trackId, user.id, body]);
		return json(res, 201, { message: 'Comment added.' });
	}
	if (action === 'community-gig') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const title = String(data.title || '').trim();
		const location = String(data.location || '').trim();
		const eventDate = String(data.eventDate || '').trim();
		const description = String(data.description || '').trim();
		const contactEmail = String(data.contactEmail || '').trim().toLowerCase();
		const type = String(data.opportunityType || 'gig');
		const compensation = String(data.compensation || '').trim();
		const parsedDate = new Date(`${eventDate}T00:00:00Z`);
		if (!['gig', 'audition', 'collaboration', 'session', 'festival', 'lesson'].includes(type)) throw new HttpError(422, 'Choose a valid opportunity type.');
		if (!title || [...title].length > 100 || !location || [...location].length > 120 || !/^\d{4}-\d{2}-\d{2}$/.test(eventDate) || Number.isNaN(parsedDate.getTime()) || parsedDate.toISOString().slice(0, 10) !== eventDate || eventDate < new Date().toISOString().slice(0, 10)) throw new HttpError(422, 'Enter a title, location, and valid future date for this opportunity.');
		if (!description || [...description].length > 1200 || [...compensation].length > 120) throw new HttpError(422, 'Add a description of up to 1200 characters and compensation details under 120 characters.');
		if (contactEmail && !validEmail(contactEmail, true)) throw new HttpError(422, 'Enter a valid public contact email or leave it blank.');
		await store.run('INSERT INTO gig_listings (poster_id, title, location, event_date, description, contact_email, opportunity_type, compensation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [user.id, title, location, eventDate, description, contactEmail, type, compensation]);
		return json(res, 201, { message: 'Your opportunity is live on the gig board.' });
	}
	if (action === 'update-musician-profile') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const existingProfile = await store.one('SELECT avatar_data, avatar_mime FROM musician_profiles WHERE user_id = ?', [user.id]);
		const profile = {
			location: String(data.location || '').trim(),
			country: String(data.country || '').trim(),
			memberType: String(data.memberType || 'singer'),
			avatarPreset: String(data.avatarPreset || 'guitar'),
			instruments: String(data.instruments || '').trim(),
			genres: String(data.genres || '').trim(),
			bio: String(data.bio || '').trim(),
			contactEmail: String(data.contactEmail || '').trim().toLowerCase(),
			language: String(data.language || 'en'),
			shareLocation: data.shareLocation === true || data.shareLocation === 'true',
			latitude: data.latitude === '' || data.latitude === undefined ? null : Number(data.latitude),
			longitude: data.longitude === '' || data.longitude === undefined ? null : Number(data.longitude),
		};
		let avatarData = existingProfile?.avatar_data || null;
		let avatarMime = existingProfile?.avatar_mime || null;
		if (data.removeAvatar === true || data.removeAvatar === 'true') {
			avatarData = null;
			avatarMime = null;
		} else if (data.avatarBase64) {
			avatarMime = String(data.avatarMime || '').toLowerCase();
			if (!['image/jpeg', 'image/png', 'image/webp'].includes(avatarMime)) throw new HttpError(422, 'Choose a JPEG, PNG, or WebP profile picture.');
			const encoded = String(data.avatarBase64);
			if (encoded.length > Math.ceil(MAX_AVATAR_IMAGE * 4 / 3) + 8 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw new HttpError(413, 'Profile pictures must be 5 MB or smaller.');
			avatarData = Buffer.from(encoded, 'base64');
			if (!avatarData.length || avatarData.length > MAX_AVATAR_IMAGE || avatarData.toString('base64') !== encoded) throw new HttpError(422, 'Choose a valid profile picture up to 5 MB.');
			const signatureValid = avatarMime === 'image/jpeg' ? avatarData[0] === 0xff && avatarData[1] === 0xd8 && avatarData[2] === 0xff
				: avatarMime === 'image/png' ? avatarData.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
				: avatarData.subarray(0, 4).toString() === 'RIFF' && avatarData.subarray(8, 12).toString() === 'WEBP';
			if (!signatureValid) throw new HttpError(422, 'The uploaded picture does not match its image format.');
		}
		if (!MEMBER_TYPES.has(profile.memberType) || !AVATAR_PRESETS.has(profile.avatarPreset) || !LANGUAGES.has(profile.language)) throw new HttpError(422, 'Choose a valid profile type, avatar, and language.');
		if ([profile.location, profile.country, profile.instruments, profile.genres].some((value) => [...value].length > 120) || [...profile.bio].length > 500) throw new HttpError(422, 'Keep location, country, instruments, and genres under 120 characters and your bio under 500.');
		if (profile.contactEmail && !validEmail(profile.contactEmail, true)) throw new HttpError(422, 'Enter a valid public contact email or leave it blank.');
		if (profile.shareLocation && (!Number.isFinite(profile.latitude) || profile.latitude < -90 || profile.latitude > 90 || !Number.isFinite(profile.longitude) || profile.longitude < -180 || profile.longitude > 180)) throw new HttpError(422, 'Allow location access to share exact coordinates, or turn off the public location toggle.');
		if (!profile.shareLocation) { profile.latitude = null; profile.longitude = null; }
		await store.run('INSERT INTO musician_profiles (user_id, location, country, member_type, avatar_preset, instruments, genres, bio, contact_email, avatar_data, avatar_mime, share_location, latitude, longitude, language, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET location = excluded.location, country = excluded.country, member_type = excluded.member_type, avatar_preset = excluded.avatar_preset, instruments = excluded.instruments, genres = excluded.genres, bio = excluded.bio, contact_email = excluded.contact_email, avatar_data = excluded.avatar_data, avatar_mime = excluded.avatar_mime, share_location = excluded.share_location, latitude = excluded.latitude, longitude = excluded.longitude, language = excluded.language, updated_at = CURRENT_TIMESTAMP', [user.id, profile.location, profile.country, profile.memberType, profile.avatarPreset, profile.instruments, profile.genres, profile.bio, profile.contactEmail, avatarData, avatarMime, profile.shareLocation ? 1 : 0, profile.latitude, profile.longitude, profile.language]);
		return json(res, 200, { message: 'Your musician profile has been updated.' });
	}
	if (action === 'update-language') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const language = String(data.language || '');
		if (!LANGUAGES.has(language)) throw new HttpError(422, 'Choose a supported language.');
		await store.run("INSERT INTO musician_profiles (user_id, language) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET language = excluded.language, updated_at = CURRENT_TIMESTAMP", [user.id, language]);
		return json(res, 200, { language, message: 'Your language preference has been saved.' });
	}
	if (action === 'community-message') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const room = String(data.room || '');
		const body = String(data.body || '').trim();
		if (!CHAT_ROOMS.has(room)) throw new HttpError(422, 'Choose a valid community room.');
		if (!body || [...body].length > 1000) throw new HttpError(422, 'Write a message between 1 and 1000 characters.');
		await store.run('INSERT INTO community_messages (room, author_id, body) VALUES (?, ?, ?)', [room, user.id, body]);
		return json(res, 201, { message: 'Message sent.' });
	}
	if (action === 'community-voice') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const room = String(data.room || '');
		const mime = String(data.audioMime || '').toLowerCase().split(';')[0];
		const encoded = String(data.audioBase64 || '');
		if (!CHAT_ROOMS.has(room)) throw new HttpError(422, 'Choose a valid community room.');
		if (!['audio/webm', 'audio/ogg', 'audio/mp4'].includes(mime)) throw new HttpError(422, 'Record a voice message in WebM, OGG, or MP4 audio format.');
		if (!encoded || encoded.length > Math.ceil(MAX_CHAT_AUDIO * 4 / 3) + 8 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw new HttpError(413, 'Voice messages must be 1.5 MB or smaller.');
		const audio = Buffer.from(encoded, 'base64');
		if (!audio.length || audio.length > MAX_CHAT_AUDIO || audio.toString('base64') !== encoded) throw new HttpError(422, 'The voice recording could not be read. Record a shorter message and try again.');
		const validSignature = mime === 'audio/webm' ? audio.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))
			: mime === 'audio/ogg' ? audio.subarray(0, 4).toString() === 'OggS'
			: audio.subarray(4, 8).toString() === 'ftyp';
		if (!validSignature) throw new HttpError(422, 'The recording does not match its audio format.');
		await store.run('INSERT INTO community_messages (room, author_id, body, audio_data, audio_mime) VALUES (?, ?, ?, ?, ?)', [room, user.id, 'Voice message', audio, mime]);
		return json(res, 201, { message: 'Voice message sent.' });
	}
	if (action === 'community-call-control') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const operation = String(data.operation || '');
		if (operation === 'create') {
			const room = String(data.room || '');
			const recipientId = Number(data.recipientId);
			const mediaType = String(data.mediaType || '');
			if (!CHAT_ROOMS.has(room) || !Number.isSafeInteger(recipientId) || recipientId < 1 || recipientId === Number(user.id) || !['audio', 'video'].includes(mediaType)) throw new HttpError(422, 'Choose a valid community member and call type.');
			const recipient = await store.one("SELECT id FROM users WHERE id = ? AND approval_status = 'approved'", [recipientId]);
			if (!recipient) throw new HttpError(404, 'That member is no longer available for a call.');
			const now = new Date().toISOString();
			await store.run("UPDATE community_calls SET status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE status IN ('ringing', 'active') AND expires_at <= ?", [now]);
			const staleCallCutoff = new Date(Date.now() - 24 * 60 * 60_000).toISOString();
			await store.run("DELETE FROM community_call_signals WHERE call_id IN (SELECT id FROM community_calls WHERE status IN ('ended', 'declined', 'expired') AND updated_at < ?)", [staleCallCutoff]);
			await store.run("DELETE FROM community_calls WHERE status IN ('ended', 'declined', 'expired') AND updated_at < ?", [staleCallCutoff]);
			const busy = await store.one("SELECT id FROM community_calls WHERE status IN ('ringing', 'active') AND expires_at > ? AND (caller_id = ? OR recipient_id = ? OR caller_id = ? OR recipient_id = ?) LIMIT 1", [now, user.id, user.id, recipientId, recipientId]);
			if (busy) throw new HttpError(409, 'One of you is already in a call. End it before starting another.');
			const id = crypto.randomUUID();
			const expiresAt = new Date(Date.now() + 45_000).toISOString();
			await store.run("INSERT INTO community_calls (id, room, caller_id, recipient_id, media_type, status, expires_at) VALUES (?, ?, ?, ?, ?, 'ringing', ?)", [id, room, user.id, recipientId, mediaType, expiresAt]);
			return json(res, 201, { callId: id, message: 'Calling member…' });
		}
		const callId = String(data.callId || '');
		if (!/^[0-9a-f-]{36}$/i.test(callId)) throw new HttpError(422, 'Choose a valid call.');
		const call = await store.one('SELECT id, caller_id, recipient_id, status FROM community_calls WHERE id = ?', [callId]);
		if (!call || (Number(call.caller_id) !== Number(user.id) && Number(call.recipient_id) !== Number(user.id))) throw new HttpError(404, 'That call is no longer available.');
		if (operation === 'accept' || operation === 'decline') {
			if (Number(call.recipient_id) !== Number(user.id) || call.status !== 'ringing') throw new HttpError(409, 'This call can no longer be answered.');
			const status = operation === 'accept' ? 'active' : 'declined';
			const expiresAt = new Date(Date.now() + 30 * 60_000).toISOString();
			await store.run('UPDATE community_calls SET status = ?, expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = ?', [status, expiresAt, callId, 'ringing']);
			return json(res, 200, { status });
		}
		if (operation === 'end') {
			if (!['ringing', 'active'].includes(String(call.status))) return json(res, 200, { status: call.status });
			await store.run("UPDATE community_calls SET status = 'ended', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status IN ('ringing', 'active')", [callId]);
			return json(res, 200, { status: 'ended' });
		}
		if (operation === 'heartbeat') {
			if (call.status !== 'active') throw new HttpError(409, 'The call is no longer active.');
			await store.run('UPDATE community_calls SET expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = ?', [new Date(Date.now() + 30 * 60_000).toISOString(), callId, 'active']);
			return json(res, 200, { status: 'active' });
		}
		if (operation === 'signal') {
			const signalType = String(data.signalType || '');
			const payload = data.payload;
			if (call.status !== 'active' && !(call.status === 'ringing' && ['offer', 'ice'].includes(signalType) && Number(call.caller_id) === Number(user.id))) throw new HttpError(409, 'The call is no longer accepting signals.');
			if (!['offer', 'answer', 'ice'].includes(signalType) || signalType === 'offer' && Number(call.caller_id) !== Number(user.id) || signalType === 'answer' && Number(call.recipient_id) !== Number(user.id)) throw new HttpError(422, 'This call signal is not valid.');
			if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) throw new HttpError(422, 'The call signal is too large or invalid.');
			const encodedPayload = JSON.stringify(payload);
			if (encodedPayload.length > 32_000) throw new HttpError(422, 'The call signal is too large or invalid.');
			const payloadValid = signalType === 'offer' || signalType === 'answer'
				? payload.type === signalType && typeof payload.sdp === 'string' && payload.sdp.length <= 28_000
				: typeof payload.candidate === 'string' && payload.candidate.length <= 2_500;
			if (!payloadValid) throw new HttpError(422, 'The call signal is incomplete.');
			await store.run('INSERT INTO community_call_signals (call_id, sender_id, signal_type, payload) VALUES (?, ?, ?, ?)', [callId, user.id, signalType, encodedPayload]);
			return json(res, 201, { message: 'Call signal sent.' });
		}
		throw new HttpError(422, 'Choose a valid call action.');
	}
	if (action === 'marketplace-listing') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const title = String(data.title || '').trim();
		const category = String(data.category || '');
		const priceAmount = Number(data.priceAmount);
		const currency = currencyForCountry(user.country_code);
		const price = Number.isFinite(priceAmount) ? priceAmount.toFixed(2) : '';
		const stock = Number(data.stock);
		const location = String(data.location || '').trim();
		const description = String(data.description || '').trim();
		const contactEmail = String(data.contactEmail || '').trim().toLowerCase();
		const imageMime = String(data.imageMime || '').toLowerCase();
		const encodedImage = String(data.imageBase64 || '');
		if (!title || [...title].length > 100 || !['instrument', 'equipment', 'accessory', 'other'].includes(category) || !currency || !Number.isFinite(priceAmount) || priceAmount <= 0 || priceAmount > 1_000_000 || Math.round(priceAmount * 100) !== priceAmount * 100 || !Number.isSafeInteger(stock) || stock < 1 || stock > 999 || [...location].length > 120 || !description || [...description].length > 1000) throw new HttpError(422, currency ? 'Enter a valid price, stock quantity, item title, location, and description within the limits shown.' : 'The shop currently supports sellers registered in Ghana (GHS) and the United States (USD).');
		if (contactEmail && !validEmail(contactEmail, true)) throw new HttpError(422, 'Enter a valid public contact email or leave it blank.');
		let imageData = null;
		if (encodedImage) {
			if (!['image/jpeg', 'image/png', 'image/webp'].includes(imageMime)) throw new HttpError(422, 'Choose a JPEG, PNG, or WebP instrument photo.');
			if (encodedImage.length > Math.ceil(MAX_MARKET_IMAGE * 4 / 3) + 8 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encodedImage)) throw new HttpError(413, 'Instrument photos must be 2 MB or smaller.');
			imageData = Buffer.from(encodedImage, 'base64');
			if (!imageData.length || imageData.length > MAX_MARKET_IMAGE || imageData.toString('base64') !== encodedImage) throw new HttpError(422, 'Choose a valid instrument photo up to 2 MB.');
			const signatureValid = imageMime === 'image/jpeg' ? imageData[0] === 0xff && imageData[1] === 0xd8 && imageData[2] === 0xff
				: imageMime === 'image/png' ? imageData.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
				: imageData.subarray(0, 4).toString() === 'RIFF' && imageData.subarray(8, 12).toString() === 'WEBP';
			if (!signatureValid) throw new HttpError(422, 'The uploaded photo does not match its image format.');
		}
		await store.run('INSERT INTO marketplace_listings (seller_id, title, category, price, price_amount, currency, stock, location, description, contact_email, image_data, image_mime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [user.id, title, category, price, priceAmount, currency, stock, location, description, contactEmail, imageData, imageData ? imageMime : null]);
		return json(res, 201, { message: 'Your listing is live in the instrument marketplace.' });
	}
	if (action === 'marketplace-checkout') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const listingId = Number(data.listingId);
		const quantity = Number(data.quantity);
		const buyerName = String(data.buyerName || '').trim();
		const buyerEmail = String(data.buyerEmail || '').trim().toLowerCase();
		const buyerPhone = String(data.buyerPhone || '').trim();
		const deliveryAddress = String(data.deliveryAddress || '').trim();
		const deliveryNote = String(data.deliveryNote || '').trim();
		if (!Number.isSafeInteger(listingId) || listingId < 1 || !Number.isSafeInteger(quantity) || quantity < 1 || quantity > 20 || !buyerName || [...buyerName].length > 80 || !validEmail(buyerEmail, true) || [...buyerPhone].length < 7 || [...buyerPhone].length > 40 || [...deliveryAddress].length < 8 || [...deliveryAddress].length > 500 || [...deliveryNote].length > 300) throw new HttpError(422, 'Enter your name, valid email, phone number, delivery address, and a quantity of 1–20.');
		const listing = await store.one("SELECT m.id, m.seller_id, m.title, m.price_amount, m.currency, m.stock FROM marketplace_listings m JOIN users u ON u.id = m.seller_id WHERE m.id = ? AND u.approval_status = 'approved'", [listingId]);
		if (!listing) throw new HttpError(404, 'That shop item is no longer available.');
		if (Number(listing.seller_id) === Number(user.id)) throw new HttpError(422, 'You cannot buy an item from your own shop.');
		if (!Number.isFinite(Number(listing.price_amount)) || Number(listing.price_amount) <= 0 || !['GHS', 'USD'].includes(String(listing.currency))) throw new HttpError(409, 'This listing is not ready for online checkout. Contact the seller directly.');
		if (Number(listing.stock) < quantity) throw new HttpError(409, 'There is not enough stock for that quantity.');
		const secret = process.env.PAYSTACK_SECRET_KEY || '';
		if (!secret) throw new HttpError(503, 'Paystack checkout is not configured. Ask the site administrator to set PAYSTACK_SECRET_KEY.');
		const amountMinor = moneyMinorUnits(Number(listing.price_amount) * quantity);
		const reference = `MW_${crypto.randomUUID().replace(/-/g, '')}`;
		await store.run("INSERT INTO marketplace_orders (listing_id, seller_id, buyer_id, quantity, amount_minor, currency, reference, status, buyer_name, buyer_email, buyer_phone, delivery_address, delivery_note) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)", [listing.id, listing.seller_id, user.id, quantity, amountMinor, listing.currency, reference, buyerName, buyerEmail, buyerPhone, deliveryAddress, deliveryNote]);
		let callbackUrl;
		try {
			callbackUrl = new URL(process.env.APP_URL || `http://${req.headers.host || 'localhost'}`);
			callbackUrl.pathname = '/';
			callbackUrl.search = new URLSearchParams({ marketplace: 'payment', reference }).toString();
		} catch { throw new HttpError(503, 'Set APP_URL to the public address of this website before enabling checkout.'); }
		let response;
		try {
			response = await fetch('https://api.paystack.co/transaction/initialize', {
				method: 'POST',
				headers: { Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json', Accept: 'application/json' },
				body: JSON.stringify({ email: buyerEmail, amount: amountMinor, currency: listing.currency, reference, callback_url: callbackUrl.toString(), metadata: { order_id: reference, listing_id: listing.id, quantity } }),
			});
		} catch {
			await store.run("UPDATE marketplace_orders SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE reference = ? AND status = 'pending'", [reference]);
			throw new HttpError(502, 'Paystack could not be reached to start checkout. Try again shortly.');
		}
		let checkout;
		try { checkout = await response.json(); } catch { checkout = null; }
		if (!response.ok || checkout?.status !== true || typeof checkout?.data?.authorization_url !== 'string') {
			await store.run("UPDATE marketplace_orders SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE reference = ? AND status = 'pending'", [reference]);
			throw new HttpError(502, String(checkout?.message || 'Paystack could not start this checkout. Check the merchant account and currency configuration.'));
		}
		return json(res, 200, { checkoutUrl: checkout.data.authorization_url, reference });
	}
	if (action === 'marketplace-order-status') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const orderId = Number(data.orderId);
		const nextStatus = String(data.status || '');
		if (!Number.isSafeInteger(orderId) || orderId < 1 || !['packing', 'shipped', 'delivered'].includes(nextStatus)) throw new HttpError(422, 'Choose a valid order update.');
		const order = await store.one('SELECT id, seller_id, status FROM marketplace_orders WHERE id = ?', [orderId]);
		if (!order) throw new HttpError(404, 'That order is no longer available.');
		if (Number(order.seller_id) !== Number(user.id) && user.role !== 'admin') throw new HttpError(403, 'Only the seller can update this delivery.');
		const allowed = { paid: 'packing', packing: 'shipped', shipped: 'delivered' };
		if (order.status === nextStatus) return json(res, 200, { message: 'Delivery status is already up to date.' });
		if (allowed[order.status] !== nextStatus) throw new HttpError(409, 'Update delivery in order: paid, preparing, shipped, then delivered.');
		await store.run('UPDATE marketplace_orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = ?', [nextStatus, orderId, order.status]);
		return json(res, 200, { message: `Order marked ${nextStatus}.` });
	}
	if (action === 'marketplace-delete') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const id = Number(data.id);
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(422, 'Choose a valid marketplace listing.');
		const listing = await store.one('SELECT seller_id FROM marketplace_listings WHERE id = ?', [id]);
		if (!listing) throw new HttpError(404, 'That marketplace listing is no longer available.');
		if (Number(listing.seller_id) !== Number(user.id) && user.role !== 'admin') throw new HttpError(403, 'You can only remove your own marketplace listings.');
		const orders = await store.one("SELECT COUNT(*) AS count FROM marketplace_orders WHERE listing_id = ? AND status IN ('pending', 'paid', 'packing', 'shipped')", [id]);
		if (Number(orders?.count || 0) > 0) throw new HttpError(409, 'This listing has an active or unpaid order and cannot be removed yet.');
		await store.run('DELETE FROM marketplace_listings WHERE id = ?', [id]);
		return json(res, 200, { message: 'Marketplace listing removed.' });
	}
	if (action === 'update-email') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const email = String(data.email || '').trim().toLowerCase();
		if (!validEmail(email, true)) throw new HttpError(422, 'Enter a valid email address.');
		try { await store.run('UPDATE users SET email = ? WHERE id = ?', [email, user.id]); }
		catch (error) { if (String(error.code || '').includes('CONSTRAINT') || /UNIQUE constraint failed/i.test(error.message)) throw new HttpError(409, 'That email address is already linked to another account.'); throw error; }
		return json(res, 200, { message: 'Email saved. You can now use it with your password to sign in.' });
	}
	if (action === 'change-password') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const currentPassword = String(data.currentPassword || '');
		const newPassword = String(data.newPassword || '');
		if (newPassword !== String(data.confirmPassword || '')) {
			throw new HttpError(422, 'The new passwords do not match.');
		}
		if (!bcrypt.compareSync(passwordMaterial(currentPassword, user.password_salt), user.password_hash)) {
			throw new HttpError(403, 'Your current password is incorrect.');
		}
		if (Buffer.byteLength(newPassword) < 12 || Buffer.byteLength(newPassword) > 1024) {
			throw new HttpError(422, 'Choose a new password between 12 and 1024 bytes.');
		}
		const passwordSalt = `${user.username}#${crypto.randomBytes(16).toString('hex')}`;
		const passwordHash = bcrypt.hashSync(passwordMaterial(newPassword, passwordSalt), 12);
		await store.run('UPDATE users SET password_salt = ?, password_hash = ?, auth_version = auth_version + 1 WHERE id = ?', [passwordSalt, passwordHash, user.id]);
		session.authVersion = Number(user.auth_version || 0) + 1;
		session.expiresAt = Date.now() + 30 * 60 * 1000;
		return json(res, 200, { message: 'Your password has been changed.' }, { 'Set-Cookie': cookie(req, session) });
	}
	if (action === 'register-signature-key') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		const encoded = String(data.publicKey || '');
		let key;
		try {
			const der = Buffer.from(encoded, 'base64');
			if (der.toString('base64') !== encoded) throw new Error();
			key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
		} catch { throw new HttpError(422, 'The signing public key is invalid.'); }
		if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new HttpError(422, 'Use an ECDSA P-256 signing key.');
		await store.run('UPDATE users SET signature_public_key = ? WHERE id = ? AND signature_public_key IS NULL', [encoded, user.id]);
		const saved = await store.one('SELECT signature_public_key FROM users WHERE id = ?', [user.id]);
		if (saved.signature_public_key !== encoded) throw new HttpError(409, 'This account already has a registered signing key. Use the browser where it was created or request an administrator key reset.');
		return json(res, 200, { publicKey: encoded });
	}
	if (action === 'change-user-role') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.role !== 'admin') throw new HttpError(403, 'Only an admin can change account roles.');
		const id = Number(data.id);
		const role = String(data.role || '');
		if (!Number.isSafeInteger(id) || id < 1 || !['admin', 'staff', 'viewer'].includes(role)) throw new HttpError(422, 'Choose a valid account and role.');
		if (id === Number(user.id)) throw new HttpError(409, 'You cannot change your own administrator role.');
		const target = await store.one('SELECT id, full_name, role FROM users WHERE id = ?', [id]);
		if (!target) throw new HttpError(404, 'Account not found.');
		if (target.role === 'admin' && role !== 'admin') {
			const admins = await store.one("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND approval_status = 'approved'");
			if (Number(admins.count) <= 1) throw new HttpError(409, 'Create or approve another admin before changing the last active admin role.');
		}
		await store.run('UPDATE users SET role = ?, auth_version = auth_version + 1 WHERE id = ?', [role, id]);
		return json(res, 200, { message: `${target.full_name}'s role is now ${role === 'viewer' ? 'Musician' : role}. They must sign in again for the change to take effect.` });
	}
	if (action === 'create-user') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.role !== 'admin') throw new HttpError(403, 'Only an admin can create accounts.');
		const role = String(data.role || '');
		if (!['admin', 'staff', 'viewer'].includes(role)) throw new HttpError(422, 'Choose the admin, staff, or viewer role.');
		const created = await createAccount(data, role);
		return json(res, 201, { user: safeUser(created), message: 'Account created. Share the initial password securely.' });
	}
	if (action === 'review-user') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.role !== 'admin') throw new HttpError(403, 'Only an admin can review access requests.');
		const id = Number(data.id);
		const decision = String(data.decision || '');
		if (!Number.isSafeInteger(id) || id < 1 || !['approve', 'decline'].includes(decision)) throw new HttpError(422, 'Choose a valid account and review decision.');
		const target = await store.one("SELECT id, username, full_name, email FROM users WHERE id = ? AND approval_status = 'pending'", [id]);
		if (!target) throw new HttpError(404, 'That access request was already reviewed or no longer exists.');
		const approved = decision === 'approve';
		const updated = await store.one("UPDATE users SET approval_status = ?, approved_at = ?, approval_due_at = NULL WHERE id = ? AND approval_status = 'pending' RETURNING id", [approved ? 'approved' : 'declined', approved ? new Date().toISOString() : null, id]);
		if (!updated) throw new HttpError(409, 'That access request was reviewed by another administrator. Refresh the dashboard.');
		const noticeSent = await sendNotice(target.email, mail.reviewNotice(target, approved));
		return json(res, 200, {
			message: approved ? `${target.full_name}'s account is approved.` : `${target.full_name}'s request was declined.`,
			noticeSent,
		});
	}
	if (action === 'delete-account') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.role !== 'admin') throw new HttpError(403, 'Only an admin can delete accounts.');
		const id = Number(data.id);
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(422, 'Invalid account.');
		const target = await store.transaction(async (tx) => {
			const account = await tx.one('SELECT * FROM users WHERE id = ?', [id]);
			if (!account) throw new HttpError(404, 'Account not found.');
			if (Number(account.id) === Number(user.id)) throw new HttpError(409, 'You cannot delete the account you are currently using. Sign in as the replacement admin first.');
			if (account.role === 'admin') {
				const admins = await tx.one("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'");
				if (Number(admins.count) <= 1) throw new HttpError(409, 'The last admin account cannot be deleted. Create a replacement admin first.');
			}
			await tx.run(
				'INSERT INTO deleted_users (original_id, username, full_name, role, email, country, country_code, approval_status, approval_due_at, created_at, approved_at, deleted_by_id, deleted_by_username, password_salt, password_hash, totp_secret, last_totp_step, failed_attempts, locked_until, auth_version, signature_public_key, google_sub) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
				[
					account.id, account.username, account.full_name, account.role, account.email || null, account.country || '', account.country_code || '', account.approval_status,
					account.approval_due_at || null, account.created_at || null, account.approved_at || null, user.id, user.username,
					account.password_salt || null, account.password_hash || null, account.totp_secret || null,
					Number(account.last_totp_step || -1), Number(account.failed_attempts || 0), Number(account.locked_until || 0),
					Number(account.auth_version || 0), account.signature_public_key || null, account.google_sub || null,
				]
			);
			await tx.run('DELETE FROM users WHERE id = ?', [id]);
			return account;
		});
		return json(res, 200, { message: `${String(target.role).replace(/^./, (letter) => letter.toUpperCase())} account deleted and archived.` });
	}
	if (action === 'restore-account') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.role !== 'admin') throw new HttpError(403, 'Only an admin can restore deleted accounts.');
		const id = Number(data.id);
		if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(422, 'Invalid deleted account.');
		const { restored, passwordRestored } = await store.transaction(async (tx) => {
			const archived = await tx.one('SELECT * FROM deleted_users WHERE id = ?', [id]);
			if (!archived) throw new HttpError(404, 'Deleted account not found in the archive.');
			const usernameTaken = await tx.one('SELECT id FROM users WHERE username = ? COLLATE NOCASE LIMIT 1', [archived.username]);
			const emailTaken = archived.email ? await tx.one('SELECT id FROM users WHERE email = ? COLLATE NOCASE LIMIT 1', [archived.email]) : null;
			if (usernameTaken || emailTaken) throw new HttpError(409, 'A live account already exists with that username or email. Choose a different identity before restoring.');
			const passwordRestored = Boolean(archived.password_salt && archived.password_hash);
			const passwordSalt = archived.password_salt || `${archived.username}#${crypto.randomBytes(16).toString('hex')}`;
			const passwordHash = archived.password_hash || bcrypt.hashSync(passwordMaterial(crypto.randomBytes(32).toString('base64url'), passwordSalt), 12);
			const result = await tx.one('INSERT INTO users (username, full_name, role, password_salt, password_hash, totp_secret, last_totp_step, failed_attempts, locked_until, auth_version, signature_public_key, email, google_sub, country, country_code, approval_status, approval_due_at, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *', [
				archived.username,
				archived.full_name,
				archived.role,
				passwordSalt,
				passwordHash,
				archived.totp_secret || null,
				Number(archived.last_totp_step || -1),
				Number(archived.failed_attempts || 0),
				Number(archived.locked_until || 0),
				Number(archived.auth_version || 0) + 1,
				archived.signature_public_key || null,
				archived.email || null,
				archived.google_sub || null,
				archived.country || '',
				archived.country_code || '',
				archived.approval_status || 'approved',
				archived.approval_due_at || null,
				archived.approved_at || null,
			]);
			await tx.run('DELETE FROM deleted_users WHERE id = ?', [id]);
			return { restored: result, passwordRestored };
		});
		const message = passwordRestored
			? `Deleted account ${restored.username} restored with its existing password.`
			: `Deleted account ${restored.username} restored, but its archived password was unavailable. The user cannot sign in with the old password.`;
		return json(res, 200, { message, passwordRestored, user: safeUser(restored) });
	}
	if (action === 'manual-backup') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.role !== 'admin') throw new HttpError(403, 'Only an admin can trigger a backup.');
		if (store.REMOTE) return json(res, 200, { message: 'The remote database provider manages its own backups.' });
		await store.maintainLocalDailyBackup();
		const backups = store.listBackups();
		return json(res, 200, { message: 'Backup created successfully.', backups });
	}
	if (action === 'restore-config') {
		if (!user) throw new HttpError(401, 'Please sign in again.');
		if (user.role !== 'admin') throw new HttpError(403, 'Only an admin can restore configuration.');
		if (store.REMOTE) throw new HttpError(400, 'Config restore is only available for local SQLite mode.');
		const filename = String(data.filename || '');
		if (!/^northstar-\d{4}-\d{2}-\d{2}\.sqlite\.enc$/.test(filename)) throw new HttpError(422, 'Invalid backup filename.');
		const date = filename.slice('northstar-'.length, 'northstar-'.length + 10);
		const backupDirectory = path.join(store.DATA_DIR, 'backups');
		const encryptedDbPath = path.join(backupDirectory, filename);
		const encryptedPepperPath = path.join(backupDirectory, `pepper-${date}.key.enc`);
		if (!fs.existsSync(encryptedDbPath)) throw new HttpError(404, 'Backup file not found.');
		const key = backupKey(store.DATA_DIR, { createIfMissing: false });
		// Restore only pepper.key (config), never overwrite the live database
		if (fs.existsSync(encryptedPepperPath)) {
			const pepperDest = path.join(store.DATA_DIR, 'pepper.key');
			const pepperTemp = `${pepperDest}.${process.pid}.${Date.now()}.tmp`;
			try {
				await decryptFile(encryptedPepperPath, pepperTemp, key, `pepper:${date}`);
				fs.renameSync(pepperTemp, pepperDest);
				try { fs.chmodSync(pepperDest, 0o600); } catch {}
			} catch (error) {
				try { fs.rmSync(pepperTemp, { force: true }); } catch {}
				throw new HttpError(500, `Config restore failed: ${error.message}`);
			}
			return json(res, 200, { message: `Configuration from backup ${date} restored. The pepper key has been updated. User data was NOT changed. Restart the server to apply.` });
		}
		return json(res, 200, { message: `No pepper key found in backup ${date}. Nothing was changed.` });
	}
	throw new HttpError(404, 'Unknown action.');
}


async function handleApi(req, res) {
	const requestId = crypto.randomUUID();
	try {
		await store.initializeDatabase();
		await autoApproveDueRequests();
		const session = readSession(req);
		const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
		await route(req, res, url, session);
	} catch (error) {
		if (error instanceof HttpError) return json(res, error.status, { error: error.message });
		const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
		console.error(`API error ${requestId} (${req.method} ${url.searchParams.get('action') || 'unknown'}):`, error);
		return json(res, 500, { error: 'The server could not complete the request.', requestId });
	}
}

module.exports = { handleApi };
