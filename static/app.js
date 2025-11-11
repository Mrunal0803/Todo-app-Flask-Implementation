(function () {
	const $ = (sel, ctx = document) => ctx.querySelector(sel);
	const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));

	// Popup
	const popup = $('#popup');
	const popupText = $('#popup-text');
	const popupClose = $('#popup-close');
	if (popup && popupClose) {
		popupClose.addEventListener('click', () => popup.classList.add('hidden'));
	}
	window.showPopup = function (text) {
		if (!popup || !popupText) return alert(text);
		popupText.textContent = text;
		popup.classList.remove('hidden');
	};

	// Convert server flashes into toasts
	(function toasts() {
		const wrap = document.createElement('div');
		wrap.id = 'toasts';
		document.body.appendChild(wrap);
		$$('#flash-messages .flash').forEach((el) => {
			const type = (el.className.split(' ').find(c => ['success','error','info'].includes(c)) || 'info');
			const t = document.createElement('div');
			t.className = `toast ${type}`;
			t.textContent = el.textContent.trim();
			wrap.appendChild(t);
			setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateY(6px)'; }, 3200);
			setTimeout(() => t.remove(), 3600);
		});
	})();

	// Mobile nav toggle
	(function mobileNav() {
		const btn = $('#nav-toggle');
		const nav = $('.nav');
		if (!btn || !nav) return;
		btn.addEventListener('click', () => nav.classList.toggle('show'));
		window.addEventListener('resize', () => { if (window.innerWidth > 720) nav.classList.remove('show'); });
	})();

	// Enhance toggle/delete with AJAX (existing behavior preserved)
	$$('form .icon-btn[data-ajax="true"]').forEach((btn) => {
		btn.addEventListener('click', function (e) {
			e.preventDefault();
			const form = this.closest('form');
			fetch(form.action, { method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
				.then(r => r.json())
				.then(() => window.location.reload())
				.catch(() => window.location.reload());
		});
	});

	// Inline client validation helpers
	$$('input[required], textarea[required]').forEach((el) => {
		el.addEventListener('invalid', () => el.classList.add('error'));
		el.addEventListener('input', () => el.classList.remove('error'));
	});
})();
