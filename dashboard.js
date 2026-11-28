'use strict';

const byId = (id) => document.getElementById(id);
const toast = byId('toast');
const toastMessage = byId('toastMessage');
let toastTimer;

requestAnimationFrame(() => document.body.classList.add('dashboard-ready'));

function showToast(message) {
	toastMessage.textContent = message;
	toast.classList.add('is-visible');
	clearTimeout(toastTimer);
	toastTimer = setTimeout(() => toast.classList.remove('is-visible'), 3200);
}

const search = byId('dashboardSearch');
const activityRows = [...document.querySelectorAll('.activity-row')];
const emptySearch = byId('emptySearch');

function filterActivity() {
	const term = search.value.trim().toLowerCase();
	let visibleCount = 0;
	activityRows.forEach((row) => {
		const searchableText = `${row.dataset.search || ''} ${row.textContent}`.toLowerCase();
		const isVisible = !term || searchableText.includes(term);
		row.hidden = !isVisible;
		if (isVisible) visibleCount += 1;
	});
	emptySearch.hidden = visibleCount !== 0;
}

search.addEventListener('input', filterActivity);
document.addEventListener('keydown', (event) => {
	if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
		event.preventDefault();
		search.focus();
	}
	if (event.key === 'Escape') {
		search.value = '';
		filterActivity();
		closeMenu();
	}
});

const sidebar = byId('sidebar');
const menuButton = byId('menuButton');
const backdrop = byId('sidebarBackdrop');

function closeMenu() {
	if (!sidebar || !menuButton || !backdrop) return;
	sidebar.classList.remove('is-open');
	backdrop.classList.remove('is-visible');
	menuButton.setAttribute('aria-expanded', 'false');
}

function toggleMenu() {
	const isOpen = !sidebar.classList.contains('is-open');
	sidebar.classList.toggle('is-open', isOpen);
	backdrop.classList.toggle('is-visible', isOpen);
	menuButton.setAttribute('aria-expanded', String(isOpen));
}

menuButton?.addEventListener('click', toggleMenu);
backdrop?.addEventListener('click', closeMenu);

const hour = new Date().getHours();
const greeting = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';

function initials(name) {
	return String(name || 'Alex Smith').trim().split(/\s+/).slice(0, 2).map((part) => part[0]).join('').toUpperCase();
}

function updateIdentity(user, profile = {}) {
	if (!user?.name) return;
	const name = String(user.name).trim();
	const firstName = name.split(/\s+/)[0] || name;
	const heading = byId('welcomeHeading');
	const memberTypes = {
		viewer: 'Viewer',
		singer: 'Singer / vocalist',
		instrumentalist: 'Instrumentalist',
		seller: 'Instrument and gear seller',
	};
	const profileType = memberTypes[profile.member_type] || '';
	const musician = ['singer', 'instrumentalist', 'seller'].includes(profile.member_type);
	const role = user.role === 'admin' ? 'Administrator' : user.role === 'staff' ? 'Staff' : profileType || 'Member';
	const roleLabel = user.role === 'admin' || user.role === 'staff' ? 'Account access' : 'Profile type';
	const userInitials = initials(name);
	if (heading) {
		heading.replaceChildren(`${greeting}, ${firstName}`, Object.assign(document.createElement('span'), { textContent: '.' }));
	}
	for (const id of ['dashboardMemberName', 'profileUserName', 'sidebarUserName']) {
		const element = byId(id);
		if (element) element.textContent = name;
	}
	for (const id of ['dashboardUsername']) {
		const element = byId(id);
		if (element) element.textContent = String(user.username || '—');
	}
	for (const id of ['dashboardRole', 'profileUserRole', 'sidebarUserRole']) {
		const element = byId(id);
		if (element) element.textContent = role;
	}
	const roleHeading = byId('dashboardRoleLabel');
	const roleCaption = byId('dashboardRoleCaption');
	if (roleHeading) roleHeading.textContent = roleLabel;
	if (roleCaption) roleCaption.textContent = user.role === 'admin' || user.role === 'staff'
		? 'Your current community role'
		: 'Your community profile';
	if (profileType) {
		document.body.dataset.memberKind = musician ? 'musician' : 'viewer';
		const welcomeCopy = byId('welcomeDescription');
		const primaryAction = document.querySelector('.welcome-actions .primary-action');
		if (welcomeCopy) welcomeCopy.textContent = musician
			? 'Share your music, meet collaborators, and find your next stage.'
			: 'Discover music, meet musicians, and join community conversations.';
		if (primaryAction) {
			primaryAction.href = musician
				? '/world.html?view=community&tab=listen'
				: '/world.html?view=community&tab=feed';
			const label = byId('primaryActionLabel');
			if (label) label.textContent = musician ? 'Share your sound' : 'Explore the community';
		}
		const shortcutItems = musician
			? [
				['Share your sound', 'Publish a track for the community.', '/world.html?view=community&tab=listen'],
				['Build your profile', 'Show the community what you play.', '/world.html?view=community&tab=musicians'],
				['Find your next stage', 'Explore gigs and collaborations.', '/world.html?view=community&tab=gigs'],
			]
			: [
				['Join the conversation', 'Share ideas and connect with members.', '/world.html?view=community&tab=feed'],
				['Discover new music', 'Listen to tracks from the community.', '/world.html?view=community&tab=listen'],
				['Meet the community', 'Find people and join conversations.', '/world.html?view=community&tab=chat'],
			];
		document.querySelectorAll('.dashboard-shortcut').forEach((link, index) => {
			const item = shortcutItems[index];
			if (!item) return;
			link.href = item[2];
			link.querySelector('strong').textContent = item[0];
			link.querySelector('small').textContent = item[1];
		});
		const activityItems = musician
			? [
				['Share a track with the community', 'Publish an audio preview or video link.', '/world.html?view=community&tab=listen'],
				['Build your musician profile', 'Show your instruments, genres, and sound.', '/world.html?view=community&tab=musicians'],
				['Find a gig or collaboration', 'Browse opportunities posted by members.', '/world.html?view=community&tab=gigs'],
			]
			: [
				['Join a community conversation', 'Share ideas and connect with members.', '/world.html?view=community&tab=feed'],
				['Listen to community music', 'Discover tracks and videos from artists.', '/world.html?view=community&tab=listen'],
				['Meet musicians', 'Find people and join conversations.', '/world.html?view=community&tab=chat'],
			];
		const activityIcons = musician ? ['i-wave', 'i-people', 'i-calendar'] : ['i-sparkle', 'i-wave', 'i-people'];
		const activityColors = ['symbol-blue', 'symbol-violet', 'symbol-teal'];
		document.querySelectorAll('.activity-row').forEach((link, index) => {
			const item = activityItems[index];
			if (!item) return;
			link.href = item[2];
			link.dataset.search = item.join(' ').toLowerCase();
			link.querySelector('strong').textContent = item[0];
			link.querySelector('small').textContent = item[1];
			const avatar = link.querySelector('.activity-avatar');
			const icon = avatar?.querySelector('use');
			if (avatar && icon) {
				avatar.classList.remove('symbol-blue', 'symbol-violet', 'symbol-teal');
				avatar.classList.add(activityColors[index]);
				icon.setAttribute('href', `#${activityIcons[index]}`);
			}
		});
		const nextStep = byId('nextStepDescription');
		const nextStepLink = document.querySelector('.schedule-card .schedule-link');
		if (nextStep) nextStep.textContent = musician
			? 'Keep your musician profile current, share new work, and explore opportunities from the community.'
			: 'Explore the listening room, join a conversation, or find musicians whose work you enjoy.';
		if (nextStepLink) {
			nextStepLink.href = musician
				? '/world.html?view=community&tab=musicians'
				: '/world.html?view=community&tab=feed';
			const label = byId('nextStepLinkLabel');
			if (label) label.textContent = musician ? 'Update your musician profile' : 'Explore the community';
		}
	}
	for (const id of ['profileAvatar', 'sidebarUserAvatar']) {
		const element = byId(id);
		if (element) element.textContent = userInitials;
	}
}

const isLoopback = location.hostname === '127.0.0.1' || location.hostname === 'localhost';
const isOpenDesignPreview = location.hostname.includes('vscode-resource') || (isLoopback && location.port !== '8001');
if (!isOpenDesignPreview) {
	fetch('/api?action=state', { credentials: 'same-origin' })
		.then((response) => {
			if (!response.ok) throw new Error('Your account could not be verified. Please sign in again.');
			return response.json();
		})
		.then(async (state) => {
			if (!state.user) {
				location.replace('/?signin=1');
				return;
			}
			updateIdentity(state.user);
			try {
				const profileResponse = await fetch('/api?action=community', { credentials: 'same-origin' });
				if (!profileResponse.ok) throw new Error('Your member profile could not be loaded.');
				const community = await profileResponse.json();
				updateIdentity(state.user, community.profile || {});
				window.setTimeout(() => showToast(`Welcome back, ${String(state.user.name).trim().split(/\s+/)[0]}. Your dashboard is ready.`), 420);
			} catch (error) {
				showToast(error.message || 'Your member profile could not be loaded.');
			}
		})
		.catch((error) => showToast(error.message || 'The dashboard could not load your account details.'));
}

document.querySelectorAll('a[href*="world.html"]').forEach((link) => {
	if (window.matchMedia('(max-width: 900px)').matches) {
		const destination = new URL(link.href, location.href);
		destination.searchParams.set('mobile', '1');
		link.href = `${destination.pathname}${destination.search}`;
	}
});
